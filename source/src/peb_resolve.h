/*
 * peb_resolve.h —— 基于 PEB 模块遍历的无导入 API 解析。
 *
 * 本项目所有 Windows API 都通过遍历进程环境块（PEB）里的加载器结构来
 * 解析，而不是走导入表或 GetModuleHandle，因此：
 *   - 二进制里不存在可疑的导入名（文件里找不到 "VirtualAlloc"、
 *     "NtCreateSection" 之类的任何字符串）；
 *   - 模块按 djb2 名称哈希匹配（见下方 djb2_hash），跨 Windows 版本稳定。
 *
 * 这里实现的 x64 关键偏移：
 *   PEB -> Ldr                      gs:[0x60] -> [+0x18]
 *   PEB->Ldr->InLoadOrderModuleList [+0x10]   （LIST_ENTRY 环形链）
 *   LDR_DATA_TABLE_ENTRY.BaseDllName [+0x58]  UNICODE_STRING {Len,Max,Ptr}
 *
 * 用法：
 *   HMODULE k32 = get_module_by_hash(0x7040EE75);          // kernel32.dll
 *   void* fn    = get_proc_by_hash(k32, 0x5FBFF0FB);       // LoadLibraryA
 * 哈希值用 djb2_hash("函数名") 预先算好——完整清单见 main.c 的 #define 区。
 */
#ifndef PEB_RESOLVE_H
#define PEB_RESOLVE_H

#include <windows.h>

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _LDR_DATA_TABLE_ENTRY_FREE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
} LDR_DATA_TABLE_ENTRY_FREE, *PLDR_DATA_TABLE_ENTRY_FREE;

typedef struct _PEB_LDR_DATA_FREE {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_FREE, *PPEB_LDR_DATA_FREE;

typedef struct _PEB_FREE {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN SpareBits : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA_FREE Ldr;
} PEB_FREE, *PPEB_FREE;

__forceinline DWORD djb2_hash(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

__forceinline DWORD djb2_hash_w(const WCHAR* str) {
    DWORD hash = 5381;
    WCHAR c;
    while ((c = *str++)) {
        if (c >= L'A' && c <= L'Z')
            c += 0x20;
        hash = ((hash << 5) + hash) + (DWORD)c;
    }
    return hash;
}

__forceinline HMODULE get_module_by_hash(DWORD hash) {
    PPEB_FREE peb;
#if defined(_WIN64)
    peb = (PPEB_FREE)__readgsqword(0x60);
#else
    peb = (PPEB_FREE)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA_FREE ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY_FREE entry = (PLDR_DATA_TABLE_ENTRY_FREE)curr;
        if (entry->BaseDllName.pBuffer != NULL) {
            if (djb2_hash_w(entry->BaseDllName.pBuffer) == hash)
                return (HMODULE)entry->DllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

__forceinline FARPROC get_proc_by_hash(HMODULE hModule, DWORD hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)hModule + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)hModule + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hModule + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)hModule + names[i]);
        if (djb2_hash(name) == hash)
            return (FARPROC)((BYTE*)hModule + functions[ordinals[i]]);
    }
    return NULL;
}

#endif

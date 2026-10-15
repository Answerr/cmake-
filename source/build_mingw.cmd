@echo off
REM 用 MinGW-w64 工具链构建 —— 这正是出厂样本使用的编译器。
REM 需要 x86_64-w64-mingw32-gcc 在 PATH 里（llvm-mingw 或 mingw-w64 均可）。
REM 输出：dist\dbghelp.dll

setlocal
cd /d %~dp0
set GCC=x86_64-w64-mingw32-gcc

%GCC% -O2 -s -nostdlib -fno-builtin -shared ^
  -e entry_dll ^
  -o dist\dbghelp.dll ^
  src\main.c ^
  exports\dbghelp_proxy.def ^
  -lkernel32 ^
  -DSD3_PHANTOM -DSD3_BLIND -DSD3_SPIN
if errorlevel 1 (
    echo [!] 构建失败
    exit /b 1
)
echo [+] 已生成 %~dp0dist\dbghelp.dll
endlocal

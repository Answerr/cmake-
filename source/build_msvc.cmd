@echo off
REM 用 MSVC/MSBuild 构建（需要 Visual Studio 2019/2022/18 的
REM "使用 C++ 的桌面开发" 工作负载，MASM 组件随 C++ 工作负载默认安装）。
REM 输出：dist\dbghelp.dll

setlocal
set SLN=%~dp0CMakeSideload.sln

for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find MSBuild\**\Bin\MSBuild.exe 2^>nul`) do set "MSB=%%i"
if not defined MSB (
    echo [!] 未找到 MSBuild.exe，请先安装 Visual Studio 的 C++ 工作负载。
    exit /b 1
)

"%MSB%" "%SLN%" -p:Configuration=Release -p:Platform=x64 -m -v:m
if errorlevel 1 (
    echo [!] 构建失败
    exit /b 1
)
echo [+] 已生成 %~dp0dist\dbghelp.dll
endlocal

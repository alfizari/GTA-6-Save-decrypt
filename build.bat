@echo off
REM Build the tiny GTA VI tag helper (DLL + CLI exe) with Visual Studio's x64 compiler.
REM Just double-click or run this from any command prompt. Keep gta6_tag_blob.bin
REM next to the resulting gta6_tag.dll / gta6_tag.exe.
setlocal
cd /d "%~dp0"

set "VCV="
REM Prefer vswhere to locate the x64 build tools, fall back to the known path.
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -find "VC\Auxiliary\Build\vcvars64.bat" 2^>nul`) do set "VCV=%%i"
if not defined VCV if exist "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "VCV=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCV if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set "VCV=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

if defined VCV (
  call "%VCV%"
) else (
  echo Could not find vcvars64.bat. Open an "x64 Native Tools Command Prompt for VS" and run: build_helper.bat
)

echo === Building gta6_tag.dll ===
cl /nologo /O2 /LD gta6_tag.c /Fe:gta6_tag.dll
echo === Building gta6_tag.exe (CLI) ===
cl /nologo /O2 /DBUILD_EXE gta6_tag.c /Fe:gta6_tag.exe
echo.
echo Done. Keep gta6_tag_blob.bin next to gta6_tag.dll / gta6_tag.exe.
endlocal

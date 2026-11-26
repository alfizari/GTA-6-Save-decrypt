@echo off
REM Build a standalone gta6_save_tool.exe with PyInstaller.
REM   build.bat          -> console exe (GUI on double-click, CLI with arguments)
REM   build.bat nocon    -> windowed exe (GUI only, no console window; CLI output is hidden)
REM Result: dist\gta6_save_tool.exe
setlocal
cd /d "%~dp0"

set "PY=python"
where %PY% >nul 2>nul || set "PY=py"
where %PY% >nul 2>nul || (
  echo Python was not found on PATH. Install Python 3.8+ from python.org and try again.
  goto :fail
)

echo === Installing / updating build dependencies ===
%PY% -m pip install --upgrade pyinstaller lz4 cryptography || goto :fail

set "MODE=--console"
if /i "%~1"=="nocon" set "MODE=--windowed"

echo === Building gta6_save_tool.exe (%MODE%) ===
%PY% -m PyInstaller --noconfirm --clean --onefile %MODE% ^
  --name gta6_save_tool ^
  --hidden-import lz4.block ^
  --collect-submodules cryptography ^
  gta6_save_tool.py || goto :fail

echo.
echo Done: %~dp0dist\gta6_save_tool.exe
endlocal
exit /b 0

:fail
echo.
echo Build FAILED.
endlocal
pause
exit /b 1

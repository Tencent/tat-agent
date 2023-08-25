@echo off
cd /d %~dp0

FOR /F "tokens=2*" %%g IN ('..\tat_agent.exe --version') do (SET VERSION=%%g)

if not exist "C:\Program Files\7-Zip\7z.exe" (
    echo "7z.exe not found, which is used for tar release files, exit now"
    exit
)

set COMPRESS_PROC="C:\Program Files\7-Zip\7z.exe"

:: generate self update file for release
:: .zip file is used for self-update but can also be used to install agent
SET FILE="tat_agent_windows_install_%VERSION%.zip"
%COMPRESS_PROC% a %FILE% install.bat uninstall.bat self_update.bat test.bat winutil.ps1 ..\tat_agent.exe ..\winpty.dll  ..\winpty-agent.exe

:: generate install file for release
SET INSTALL_DIR="tat_agent_windows_install_%VERSION%"
if not exist %INSTALL_DIR% (
    md %INSTALL_DIR%
)
for %%i in (..\tat_agent.exe ..\winpty.dll  ..\winpty-agent.exe install.bat uninstall.bat test.bat winutil.ps1) do ( copy %%i %INSTALL_DIR% )
set FILE="%INSTALL_DIR%.tar.gz"
:: del old file
del %FILE% >nul 2>&1
%COMPRESS_PROC% a -ttar -so -an %INSTALL_DIR% | %COMPRESS_PROC% a -si %FILE%
rd /s/q %INSTALL_DIR%

:: generate uninstall file for release
SET UNINSTALL_DIR=".\tat_agent_windows_uninstall_%VERSION%"
if not exist %UNINSTALL_DIR% (
    md %UNINSTALL_DIR%
)
copy uninstall.bat %UNINSTALL_DIR%
set FILE="%UNINSTALL_DIR%.tar.gz"
:: del old file
del %FILE% >nul 2>&1
%COMPRESS_PROC% a -ttar -so -an %UNINSTALL_DIR% | %COMPRESS_PROC% a -si %FILE%
rd /s/q %UNINSTALL_DIR%


SET DATA_DIR=".\tmpdata"
if not exist %DATA_DIR% (
    md %DATA_DIR%
)
SET WINPTY_AGENT="..\target\release\winpty-agent.exe"
SET TAT_AGENT="..\target\release\tat_agent.exe"
SET WINPTY_DLL="..\target\release\winpty.dll"
COPY winutil.ps1 %DATA_DIR%
COPY %WINPTY_AGENT% %DATA_DIR%
COPY %TAT_AGENT% %DATA_DIR%
COPY %WINPTY_DLL% %DATA_DIR%

if exist "data.zip" (
    DEL "data.zip"
)
%COMPRESS_PROC% a "data.zip" %DATA_DIR%

if exist "..\target\release\tat_agent_installer.exe" (
    DEL "..\target\release\tat_agent_installer.exe"
)
cargo build -r --bin packager
REN "..\target\release\packager.exe" "tat_agent_installer.exe"
RD /s/q %DATA_DIR%
CD ..

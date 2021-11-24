@echo off
cd /d %~dp0

set SIGNED_AGENT="..\tat_agent.exe"
FOR /F "tokens=2*" %%g IN ('%SIGNED_AGENT% --version') do (SET VERSION=%%g)

if not exist "C:\Program Files\7-Zip\7z.exe" (
    echo "7z.exe not found, which is used for tar release files, exit now"
    exit
)

set COMPRESS_PROC="C:\Program Files\7-Zip\7z.exe"

:: generate self update file for release
SET FILE="tat_agent_windows_update_%VERSION%.zip"
%COMPRESS_PROC% a %FILE% %SIGNED_AGENT% install.bat uninstall.bat self_update.bat test.bat

:: generate install file for release
SET INSTALL_DIR="tat_agent_windows_install_%VERSION%"
if not exist %INSTALL_DIR% (
    md %INSTALL_DIR%
)
for %%i in (%SIGNED_AGENT% install.bat uninstall.bat test.bat) do ( copy %%i %INSTALL_DIR% )
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

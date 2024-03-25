@echo off
cd /d %~dp0

if "%1" == "win64-bin" goto win64-bin
if "%1" == "win64-update-pkg" goto win64-update-pkg
if "%1" == "win64-install-pkg" goto win64-install-pkg
if "%1" == "win64-installer" goto win64-installer
if "%1" == "test" goto test
echo "Please provide an argument: win64-bin|win64-update-pkg|win64-install-pkg|win64-installer|test"
goto end

:test
    cargo test --package tat_agent -- --nocapture --skip ontime --skip executor::thread::tests::test_cancel  --skip executor::proc::tests::test_shell_cmd_timeout
    goto end
    
:win64-bin
    SET RUSTFLAGS=-C target-feature=+crt-static
    rustup target add x86_64-pc-windows-msvc
    cargo build --release --target x86_64-pc-windows-msvc
    rd /s/q release\win-64
    mkdir release\win-64
    copy /Y target\x86_64-pc-windows-msvc\release\tat_agent.exe release\win-64\tat_agent.exe
    copy /Y winpty\winpty.dll release\win-64\winpty.dll
    copy /Y winpty\winpty-agent.exe release\win-64\winpty-agent.exe
    copy /Y install\*.bat release\win-64\
    copy /Y install\*.ps1 release\win-64\
    goto end


:win64-update-pkg
    cd .\release\win-64
    FOR /F "tokens=2*" %%g IN ('.\tat_agent.exe --version') do (SET VERSION=%%g)
    set COMPRESS_PROC="C:\Program Files\7-Zip\7z.exe"
    SET FILE="..\tat_agent_windows_install_%VERSION%.zip"
    %COMPRESS_PROC% a %FILE% .\*
    cd ..\..\
    goto end

:win64-install-pkg 
    if not exist "C:\Program Files\7-Zip\7z.exe" (
        echo "7z.exe not found, which is used for tar release files, exit now"
        exit
    )
    SET COMPRESS_PROC="C:\Program Files\7-Zip\7z.exe"
    FOR /f "delims=@ tokens=2" %%a in ('cargo pkgid') do set VERSION=%%a
   
    SET PKG_DIR=tat_agent_windows_install_%VERSION%
    rd /s/q .\release\%PKG_DIR%
    mkdir .\release\%PKG_DIR%
    cd .\release\%PKG_DIR%

    SET FILE="tat_agent_windows_install_%VERSION%.tar.gz"
    del ..\%FILE%

    copy ..\win-64\*  .\
    %COMPRESS_PROC% a -ttar -so -r *  |  %COMPRESS_PROC% a -si ..\%FILE%

    cd ..\..\
    rd /s/q .\release\%PKG_DIR%
    goto end


:win64-installer
    if exist ".\install\win-bin.zip" (
        del ".\install\win-bin.zip"
    )
    SET RUSTFLAGS=-C target-feature=+crt-static
    set COMPRESS_PROC="C:\Program Files\7-Zip\7z.exe"
    %COMPRESS_PROC% a ".\install\win-bin.zip"  ".\release\win-64\*"
    cargo build --bin installer --release --target x86_64-pc-windows-msvc
    copy /Y target\x86_64-pc-windows-msvc\release\installer.exe release\win-64\tat_agent_installer.exe
:end
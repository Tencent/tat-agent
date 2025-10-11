@ECHO OFF
GOTO:MAIN

:INSTALL
    SETLOCAL ENABLEDELAYEDEXPANSION
        :: Install-Files
        ECHO "=>Install-Files"
        SET sysDrive=%SystemDrive%
        IF "%systemDrive%"=="" SET sysDrive=C:
        SET agentDir=%sysDrive%\Program Files\QCloud\tat_agent
        SET agentPath=%agentDir%\tat_agent.exe

        SET  temp=%TIME%
        SET "temp=%temp::=%"
        SET "temp=%temp:.=%"

        IF NOT EXIST "%agentDir%" MKDIR "%agentDir%"
        IF NOT EXIST "%agentDir%\workdir" MKDIR "%agentDir%\workdir"

        CD /D %agentDir%
        IF EXIST "%agentPath%" REN "tat_agent.exe" "temp_agent_%temp%.exe"
        IF EXIST "%agentDir%\winpty.dll" REN "winpty.dll" "temp_winpty_%temp%.dll"
        IF EXIST "%agentDir%\winpty-agent.exe" REN "winpty-agent.exe" "temp_winpty_%temp%.exe"

        CD /D %~dp0
        COPY /Y "tat_agent.exe" "%agentDir%\tat_agent.exe" > NUL
        COPY /Y "winpty-agent.exe" "%agentDir%\winpty-agent.exe" > NUL
        COPY /Y "winpty.dll" "%agentDir%\winpty.dll" > NUL

        :: Install-Service
        ECHO "=>Install-Service"
        sc.exe query tatsvc > NUL 2>&1
        IF ERRORLEVEL 1 (
            ECHO "install new service"
            sc.exe create tatsvc binPath= "\"%agentPath%\"" start= auto
            sc.exe failure tatsvc actions= restart/1000 reset= -1
        ) ELSE (
            sc.exe config tatsvc binPath= "\"%agentPath%\""
        )
    ENDLOCAL
EXIT /B 0

:START
    SETLOCAL ENABLEDELAYEDEXPANSION
        sc.exe start tatsvc > NUL
    ENDLOCAL
EXIT /B 0

:STOP
    SETLOCAL ENABLEDELAYEDEXPANSION
        sc.exe stop tatsvc > NUL
    ENDLOCAL
EXIT /B 0

:MAIN
SET "param=%1"
IF /I "%param%"=="only_update" (
    CALL :INSTALL
    GOTO :END
)
IF /I "%param%"=="restart" (
    CALL :STOP
    CALL :START
    GOTO :END
)
IF "%param%"=="" (
    CALL :INSTALL
    CALL :START
    GOTO :END
)
:END
@echo off
cd /d %~dp0

if not exist "C:\Program Files\qcloud\tat_agent" (
    md "C:\Program Files\qcloud\tat_agent"
)

if not exist "C:\Program Files\qcloud\tat_agent\workdir" (
    md "C:\Program Files\qcloud\tat_agent\workdir"
)

sc query tatsvc | find "STATE" >nul  && sc stop tatsvc >nul ||^
sc create tatsvc binPath= "C:\Program Files\qcloud\tat_agent\tat_agent.exe" start= auto

copy /Y tat_agent.exe "C:\Program Files\qcloud\tat_agent\tat_agent.exe"

sc failure tatsvc actions= restart/1000 reset= -1 >nul

sc start tatsvc
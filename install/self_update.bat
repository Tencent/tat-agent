cd /d %~dp0
set  temp=%TIME%
set "temp=%temp::=%"
set "temp=%temp:.=%"
set  newname=temp_%temp%.exe
rename "C:\Program Files\qcloud\tat_agent\tat_agent.exe" %newname%
copy /Y tat_agent.exe "C:\Program Files\qcloud\tat_agent\"

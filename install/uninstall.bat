sc stop tatsvc
sc delete tatsvc
set sysDrive=%SystemDrive%
if "%systemDrive%"=="" set sysDrive=C:
rd /s/q "%sysDrive%\Program Files\QCloud\tat_agent"
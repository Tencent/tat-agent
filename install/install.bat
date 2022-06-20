@echo off
cd /d %~dp0
sc stop tatsvc > NUL
powershell -ExecutionPolicy Bypass .\winutil.ps1
sc start tatsvc
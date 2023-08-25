@echo off
cd /d %~dp0
powershell -ExecutionPolicy Bypass .\winutil.ps1
sc start tatsvc > NUL
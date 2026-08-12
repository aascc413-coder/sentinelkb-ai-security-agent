@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\start_project.ps1"
if errorlevel 1 pause

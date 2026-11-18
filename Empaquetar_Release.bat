@echo off
rem Compila InventarioTI.exe y genera dist\InventarioTI_v<version>.zip (exe + .bat de respaldo autonomo)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build\empaquetar_release.ps1"
set "RC=%ERRORLEVEL%"
if /i not "%~1"=="/nopause" pause
exit /b %RC%

@echo off
chcp 65001 >nul
pushd "%~dp0"
title Iniciando Sistema de Inventario TI (C# Nativo)...
color 0B

set "INV_BASE_DIR=%~dp0"
set "CS_FILE=%~dp0src\InventarioApp.cs"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Sta -Command ^
  "$csCode = Get-Content -LiteralPath $env:CS_FILE -Raw -Encoding UTF8; " ^
  "$refs = @('System.dll','System.Core.dll','System.Data.dll','System.Drawing.dll','System.Windows.Forms.dll','System.Management.dll','System.DirectoryServices.dll','System.IO.Compression.dll','System.IO.Compression.FileSystem.dll','System.Web.Extensions.dll','System.Xml.dll'); " ^
  "Add-Type -TypeDefinition $csCode -ReferencedAssemblies $refs -ErrorAction Stop; " ^
  "[SistemaInventarioTI.Program]::StartApp()"

popd
exit /b
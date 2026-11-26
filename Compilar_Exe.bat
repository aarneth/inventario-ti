@echo off
setlocal
pushd "%~dp0"
title Compilando InventarioTI.exe...

rem Compilador C# 5 incluido en .NET Framework 4.x (ya viene en Windows 10/11, no requiere instalar nada)
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo [ERROR] No se encontro csc.exe de .NET Framework 4.x
    popd
    pause
    exit /b 1
)

set "OUT=%~dp0InventarioTI.exe"

rem Copia del codigo con la credencial de Google Drive (build\google_oauth.local.json, fuera del repo)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "build\preparar_fuente.ps1"
if errorlevel 1 (
    echo [ERROR] No se pudo preparar el codigo fuente.
    popd
    if /i not "%~1"=="/nopause" pause
    exit /b 1
)

rem /codepage:65001 es obligatorio: el .cs esta en UTF-8 sin BOM y contiene tildes
"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 ^
  /win32manifest:"src\app.manifest" ^
  /out:"%OUT%" ^
  /r:System.dll /r:System.Core.dll /r:System.Data.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll ^
  /r:System.Management.dll /r:System.DirectoryServices.dll /r:System.IO.Compression.dll ^
  /r:System.IO.Compression.FileSystem.dll /r:System.Web.Extensions.dll /r:System.Xml.dll ^
  "obj\InventarioApp.build.cs"

if errorlevel 1 (
    echo.
    echo [ERROR] La compilacion fallo. Revisa los mensajes de arriba.
    popd
    pause
    exit /b 1
)

echo.
echo [OK] Generado: %OUT%
echo.
echo Hash SHA-256 (enviar a Seguridad TI para la lista blanca de Kaspersky):
certutil -hashfile "%OUT%" SHA256 | findstr /v /c:"CertUtil" /c:"SHA256"
echo.
echo NOTA: cada recompilacion cambia el hash; hay que volver a solicitar la excepcion.

popd
if /i not "%~1"=="/nopause" pause
endlocal

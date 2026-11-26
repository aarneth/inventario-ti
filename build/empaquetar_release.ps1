# Genera el paquete de distribucion para USB/SSD de los tecnicos:
#   dist\InventarioTI_v<version>.zip  ->  InventarioTI.exe + Iniciar_Inventario.bat (respaldo autonomo)
# La version se toma de [assembly: AssemblyVersion] en src\InventarioApp.cs (unica fuente).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$csPath = Join-Path $root 'src\InventarioApp.cs'
$cs = [IO.File]::ReadAllText($csPath, [Text.Encoding]::UTF8)

$mv = [regex]::Match($cs, 'AssemblyVersion\("(\d+)\.(\d+)\.(\d+)\.\d+"\)')
if (-not $mv.Success) { throw 'No se encontro AssemblyVersion en src\InventarioApp.cs' }
$version = '{0}.{1}.{2}' -f $mv.Groups[1].Value, $mv.Groups[2].Value, $mv.Groups[3].Value

$manifest = [IO.File]::ReadAllText((Join-Path $root 'src\app.manifest'))
if ($manifest -notmatch ('assemblyIdentity version="' + [regex]::Escape($version) + '\.0"')) {
    throw "La version de src\app.manifest no coincide con AssemblyVersion ($version.0). Actualizala antes de empaquetar."
}
Write-Host "Version: $version"

# 1. Compilar el .exe
& cmd.exe /c "`"$root\Compilar_Exe.bat`" /nopause"
if ($LASTEXITCODE -ne 0) { throw 'Fallo la compilacion de InventarioTI.exe' }

# 2. Preparar carpeta de salida
$name = "InventarioTI_v$version"
$dist = Join-Path $root 'dist'
$stage = Join-Path $dist $name
$zip = Join-Path $dist "$name.zip"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
if (Test-Path $zip) { Remove-Item $zip -Force }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item (Join-Path $root 'InventarioTI.exe') $stage

# 3. Generar Iniciar_Inventario.bat autonomo: cabecera + marcador + codigo C#
#    El marcador se arma por concatenacion dentro del comando para que IndexOf no lo encuentre en la cabecera.
# IMPORTANTE: no cambiar la cabecera del .bat entre versiones. La actualizacion automatica reemplaza el .bat
# mientras cmd.exe lo esta ejecutando; cmd retoma la lectura en la misma posicion, que con una cabecera
# identica cae en las mismas lineas finales (if errorlevel / popd / exit).
$marker = '//###CODIGO_CSHARP###'
$header = @'
@echo off
rem ===================================================================
rem  Sistema de Inventario TI - lanzador de RESPALDO (autonomo)
rem  Usar solo si InventarioTI.exe no se puede ejecutar en este equipo.
rem  El codigo C# va incluido al final de este archivo: NO editarlo a mano.
rem  Se genera con Empaquetar_Release.bat a partir de src\InventarioApp.cs.
rem ===================================================================
chcp 65001 >nul
pushd "%~dp0"
title Iniciando Sistema de Inventario TI (respaldo)...

set "INV_BASE_DIR=%~dp0"
set "INV_SELF=%~f0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Sta -Command ^
  "$t = [IO.File]::ReadAllText($env:INV_SELF, [Text.Encoding]::UTF8); " ^
  "$m = '//' + '###CODIGO_CSHARP###'; $i = $t.IndexOf($m); " ^
  "if ($i -lt 0) { throw 'No se encontro el codigo C# dentro de este .bat' }; " ^
  "$csCode = $t.Substring($i + $m.Length); " ^
  "$refs = @('System.dll','System.Core.dll','System.Data.dll','System.Drawing.dll','System.Windows.Forms.dll','System.Management.dll','System.DirectoryServices.dll','System.IO.Compression.dll','System.IO.Compression.FileSystem.dll','System.Web.Extensions.dll','System.Xml.dll'); " ^
  "Add-Type -TypeDefinition $csCode -ReferencedAssemblies $refs -ErrorAction Stop; " ^
  "[SistemaInventarioTI.Program]::StartApp()"
if errorlevel 1 pause

popd
exit /b
'@
$header = ($header -replace "`r?`n", "`r`n")
# El .bat lleva el mismo codigo que el .exe (con la credencial de Google Drive si existe build\google_oauth.local.json)
$csBuild = [IO.File]::ReadAllText((Join-Path $root 'obj\InventarioApp.build.cs'), [Text.Encoding]::UTF8)
$csCrlf = ($csBuild -replace "`r?`n", "`r`n")
$batText = $header + "`r`n" + $marker + "`r`n" + $csCrlf
# UTF-8 SIN BOM: un BOM rompe la primera linea (@echo off) en cmd.exe
[IO.File]::WriteAllText((Join-Path $stage 'Iniciar_Inventario.bat'), $batText, (New-Object Text.UTF8Encoding($false)))

# 4. Comprimir
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal

Write-Host ''
Write-Host "[OK] Paquete: $zip"
Write-Host ''
Write-Host 'SHA-256:'
foreach ($f in @((Join-Path $stage 'InventarioTI.exe'), (Join-Path $stage 'Iniciar_Inventario.bat'), $zip)) {
    $h = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
    Write-Host ('  {0,-28} {1}' -f (Split-Path $f -Leaf), $h)
}

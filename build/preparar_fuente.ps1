# Prepara el codigo que se compila: copia src\InventarioApp.cs en obj\InventarioApp.build.cs e inserta la
# credencial de Google Drive (Client ID / Secret de "app de escritorio") desde build\google_oauth.local.json.
# Ese archivo NO se versiona (.gitignore): asi la credencial va en el .exe/.bat del release pero no en el repo.
# Sin el archivo, se compila igual y la conexion con Google Drive aparece como "no configurada".
# Formato aceptado: el JSON que descarga Google Cloud ({"installed":{"client_id":...,"client_secret":...}})
# o uno simple {"client_id":"...","client_secret":"..."}. Ver docs\GOOGLE_DRIVE.md.
param([string]$Root = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'

$src = Join-Path $Root 'src\InventarioApp.cs'
$objDir = Join-Path $Root 'obj'
$out = Join-Path $objDir 'InventarioApp.build.cs'
$cfg = Join-Path $Root 'build\google_oauth.local.json'

$code = [IO.File]::ReadAllText($src, [Text.Encoding]::UTF8)
if (Test-Path $cfg) {
    $j = Get-Content $cfg -Raw -Encoding UTF8 | ConvertFrom-Json
    $node = $j
    if ($j.installed) { $node = $j.installed }
    $id = [string]$node.client_id
    $secret = [string]$node.client_secret
    if ($id -notmatch '^[\w.-]+\.apps\.googleusercontent\.com$') { throw "client_id no valido en $cfg" }
    if ($secret -notmatch '^[\w-]+$') { throw "client_secret no valido en $cfg" }
    $code = $code.Replace('"__GOOGLE_CLIENT_ID__"', '"' + $id + '"').Replace('"__GOOGLE_CLIENT_SECRET__"', '"' + $secret + '"')
    Write-Host '[OK] Credencial de Google Drive incluida en la compilacion.'
} else {
    Write-Host '[AVISO] Sin build\google_oauth.local.json: Google Drive quedara como "no configurado" en esta compilacion.'
}
if (-not (Test-Path $objDir)) { New-Item -ItemType Directory $objDir | Out-Null }
[IO.File]::WriteAllText($out, $code, (New-Object Text.UTF8Encoding($false)))

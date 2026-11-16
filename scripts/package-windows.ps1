$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$exe = Join-Path $repo 'target\x86_64-pc-windows-gnu\release\capyvault-app.exe'
$mingw = 'C:\msys64\mingw64\bin'
$distRoot = Join-Path $repo 'dist'
$packageName = 'CapyVault-Windows-x64'
$packageDir = Join-Path $distRoot $packageName
$zipPath = Join-Path $distRoot "$packageName.zip"

if (-not (Test-Path -LiteralPath $exe)) {
    throw "No existe el ejecutable de distribución: $exe"
}

New-Item -ItemType Directory -Force -Path $distRoot | Out-Null
if (Test-Path -LiteralPath $packageDir) {
    Remove-Item -LiteralPath $packageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $packageDir | Out-Null
Copy-Item -LiteralPath $exe -Destination $packageDir

foreach ($dll in @('libstdc++-6.dll', 'libgcc_s_seh-1.dll', 'libwinpthread-1.dll')) {
    $source = Join-Path $mingw $dll
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Falta la biblioteca de ejecución requerida: $source"
    }
    Copy-Item -LiteralPath $source -Destination $packageDir
}

Copy-Item -LiteralPath (Join-Path $repo 'README.md') -Destination (Join-Path $packageDir 'LEEME.md')
Copy-Item -LiteralPath (Join-Path $repo 'docs') -Destination $packageDir -Recurse
@'
CapyVault para Windows x64

Ejecuta capyvault-app.exe. No requiere instalación ni privilegios de administrador.
La primera vez, crea una bóveda en la carpeta que elijas. Guarda su clave de
recuperación fuera del USB. Nunca guardes la clave junto a la bóveda.

La bóveda y sus copias se cifran. Los archivos CSV y XLSX exportados son texto
legible; exporta solo después de revisar la advertencia de la aplicación.

Este paquete se ha creado sin firma digital. Las DLL incluidas son el entorno
de ejecución de MinGW necesario para el ejecutable Windows GNU.
'@ | Set-Content -LiteralPath (Join-Path $packageDir 'LEEME.txt') -Encoding utf8

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -Path (Join-Path $packageDir '*') -DestinationPath $zipPath -CompressionLevel Optimal
Get-FileHash -LiteralPath $zipPath -Algorithm SHA256 |
    Select-Object Algorithm, Hash, Path |
    Export-Csv -LiteralPath (Join-Path $distRoot "$packageName.sha256.csv") -NoTypeInformation -Encoding utf8

Get-Item -LiteralPath $zipPath | Select-Object FullName, Length
Get-FileHash -LiteralPath $zipPath -Algorithm SHA256 | Select-Object Hash

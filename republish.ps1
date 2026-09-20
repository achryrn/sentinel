$ErrorActionPreference = 'Stop'
# republish.ps1 - rebuilds the production tree under dist\Sentinel from source.
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $root 'dist' 'Sentinel'
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }

dotnet publish (Join-Path $root 'src\Sentinel.Service\Sentinel.Service.csproj') -c Release -r win-x64 --self-contained false -o (Join-Path $dist 'service') --nologo -v q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
dotnet publish (Join-Path $root 'src\Sentinel.Cli\Sentinel.Cli.csproj') -c Release -r win-x64 --self-contained false -o (Join-Path $dist 'cli') --nologo -v q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
dotnet publish (Join-Path $root 'src\Sentinel.Gui\Sentinel.Gui.csproj') -c Release -r win-x64 --self-contained false -o (Join-Path $dist 'gui') --nologo -v q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
dotnet publish (Join-Path $root 'src\Sentinel.Setup\Sentinel.Setup.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o (Join-Path $dist 'tools') --nologo -v q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Copy-Item (Join-Path $root 'tools\dist-templates\*') $dist -Recurse -Force
Write-Host ''
Write-Host 'Production tree ready at: ' + $dist
Write-Host '  install with:  ' + (Join-Path $dist 'install.bat')

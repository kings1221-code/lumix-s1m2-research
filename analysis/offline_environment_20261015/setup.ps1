param(
    [Parameter(Mandatory=$true)][string]$Python,
    [string]$Cache,
    [switch]$AllowDownload
)
$ErrorActionPreference = 'Stop'
$researchRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$bootstrapArgs = @('-I', (Join-Path $PSScriptRoot 'bootstrap.py'))
if ($Cache) { $bootstrapArgs += @('--cache', $Cache) }
if ($AllowDownload) { $bootstrapArgs += '--allow-download' }
& $Python @bootstrapArgs
if ($LASTEXITCODE -ne 0) { throw 'Official tool bootstrap failed' }
$researchPython = Join-Path $researchRoot '.research-local\venv\Scripts\python.exe'
$researchWheels = Join-Path $researchRoot '.research-local\downloads'
$researchTemp = Join-Path $researchRoot '.research-local\tmp'
New-Item -ItemType Directory -Path $researchTemp -Force | Out-Null
$previousResearchTemp = $env:TEMP
$previousResearchTmp = $env:TMP
try {
    $env:TEMP = $researchTemp
    $env:TMP = $researchTemp
    & $researchPython -I -m pip install --disable-pip-version-check --no-cache-dir --no-index --find-links $researchWheels --only-binary=:all: --no-deps --require-hashes -r (Join-Path $PSScriptRoot 'requirements.lock')
    if ($LASTEXITCODE -ne 0) { throw 'Locked offline wheel installation failed' }
} finally {
    $env:TEMP = $previousResearchTemp
    $env:TMP = $previousResearchTmp
}
Write-Output 'Environment ready. Use .research-local\venv\Scripts\python.exe explicitly; no global PATH changes.'

param(
  [Parameter(Mandatory = $true)]
  [string]$UbuntuUser,

  [string]$UbuntuHost = $env:SURICATA_SSH_HOST,
  [int]$Port = 22,
  [string]$KeyPath = (Join-Path $PSScriptRoot "suricata_key"),
  [switch]$Bootstrap,
  [switch]$SkipValidate,
  [switch]$SkipSync
)

$python = Join-Path $PSScriptRoot "..\venv\Scripts\python.exe"
$python = [System.IO.Path]::GetFullPath($python)

if (-not (Test-Path $python)) {
  throw "Python virtual environment not found at $python"
}

if (-not $UbuntuHost) {
  throw "Provide -UbuntuHost or set SURICATA_SSH_HOST."
}

if (-not (Test-Path $KeyPath)) {
  throw "SSH key not found at $KeyPath"
}

Push-Location $PSScriptRoot
try {
  & $python manage.py configure_suricata_sync --user $UbuntuUser --host $UbuntuHost --port $Port --key-path $KeyPath
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to write Suricata sync config"
  }

  if ($Bootstrap) {
    $bootstrapArgs = @("manage.py", "bootstrap_suricata_remote")
    if ($SkipValidate) {
      $bootstrapArgs += "--skip-validate"
    }
    & $python @bootstrapArgs
    if ($LASTEXITCODE -ne 0) {
      throw "Remote Suricata bootstrap failed"
    }
  }

  if (-not $SkipSync) {
    & $python manage.py sync_suricata_remote
    if ($LASTEXITCODE -ne 0) {
      throw "Remote Suricata sync failed"
    }
  }
}
finally {
  Pop-Location
}

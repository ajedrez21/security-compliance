<#
.SYNOPSIS
  Instala security-compliance (sin administrador, sin cambiar políticas de PowerShell).
.EXAMPLE
  .\install.ps1 -Client cursor -Scope global
  .\install.ps1 -Client claude -Scope project -ProjectPath C:\repos\mi-app
  .\install.ps1 -Client codex -Scope global -Update
  .\install.ps1 -Client cursor -Scope global -Uninstall
.NOTES
  Si la ejecución de scripts está bloqueada, ejecute: powershell -ExecutionPolicy Bypass -File .\install.ps1 ...
  (el instalador no modifica la política global).
#>
[CmdletBinding()]
param(
  [ValidateSet('cursor', 'claude', 'codex')][string[]]$Client,
  [ValidateSet('global', 'project')][string]$Scope,
  [string]$ProjectPath,
  [ValidateSet('assisted', 'manual')][string]$Invocation = 'assisted',
  [switch]$Update,
  [switch]$Uninstall,
  [switch]$DryRun,
  [switch]$Force,
  [switch]$NonInteractive
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Resolver Python >= 3.9: py -3, python, python3
$py = $null
foreach ($cand in @(@('py', '-3'), @('python'), @('python3'))) {
  $exe = $cand[0]
  if (Get-Command $exe -ErrorAction SilentlyContinue) {
    $pre = @(); if ($cand.Length -gt 1) { $pre = $cand[1..($cand.Length - 1)] }
    & $exe @pre -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $py = @{ exe = $exe; pre = $pre }; break }
  }
}
if (-not $py) {
  Write-Error "Se requiere Python >= 3.9 (py -3, python o python3 en PATH). El instalador no instala Python."
  exit 2
}

$argsList = @()
foreach ($c in $Client) { $argsList += @('--client', $c) }
if ($Scope) { $argsList += @('--scope', $Scope) }
if ($ProjectPath) { $argsList += @('--project-path', $ProjectPath) }
$argsList += @('--invocation', $Invocation)
if ($Update) { $argsList += '--update' }
if ($Uninstall) { $argsList += '--uninstall' }
if ($DryRun) { $argsList += '--dry-run' }
if ($Force) { $argsList += '--force' }
if ($NonInteractive) { $argsList += '--non-interactive' }

& $py.exe @($py.pre) (Join-Path $here 'installer\sc_install.py') @argsList
exit $LASTEXITCODE

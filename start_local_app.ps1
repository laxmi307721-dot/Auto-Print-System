$ErrorActionPreference = 'Stop'

$projectRoot = $PSScriptRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
$serverScript = Join-Path $projectRoot 'app.py'
$agentScript = Join-Path $projectRoot 'print_agent.py'
$logDirectory = Join-Path $projectRoot 'logs'

foreach ($requiredPath in @($python, $serverScript, $agentScript)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required Auto Print System file was not found: $requiredPath"
    }
}

New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null

Start-Process `
    -FilePath $python `
    -ArgumentList @($serverScript) `
    -WorkingDirectory $projectRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $logDirectory 'server.log') `
    -RedirectStandardError (Join-Path $logDirectory 'server-error.log')

Start-Sleep -Seconds 3

Start-Process `
    -FilePath $python `
    -ArgumentList @($agentScript) `
    -WorkingDirectory $projectRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $logDirectory 'print-agent.log') `
    -RedirectStandardError (Join-Path $logDirectory 'print-agent-error.log')

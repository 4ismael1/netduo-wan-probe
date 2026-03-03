$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$envFile = ".env"
$outFile = "netduo_probe_connection.txt"

function Test-Command($name) {
    return $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

if (-not (Test-Command "docker")) {
    Write-Host "Docker no esta instalado. Instala Docker y vuelve a ejecutar."
    exit 1
}

$composeCmd = $null
try {
    docker compose version | Out-Null
    $composeCmd = "docker compose"
} catch {
    if (Test-Command "docker-compose") {
        $composeCmd = "docker-compose"
    } else {
        Write-Host "No se encontro docker compose."
        exit 1
    }
}

if (-not (Test-Path $envFile)) {
    Copy-Item ".env.example" $envFile
}

function New-ApiKey {
    return -join ((1..48) | ForEach-Object { "0123456789abcdef"[(Get-Random -Minimum 0 -Maximum 16)] })
}

$envLines = Get-Content $envFile

function Set-EnvValue([string]$key, [string]$value) {
    $pattern = "^$key="
    $global:envLines = $global:envLines | ForEach-Object {
        if ($_ -match $pattern) { "$key=$value" } else { $_ }
    }
    if (-not ($global:envLines | Where-Object { $_ -match $pattern })) {
        $global:envLines += "$key=$value"
    }
}

function Get-EnvValue([string]$key) {
    $line = $global:envLines | Where-Object { $_ -match "^$key=" } | Select-Object -First 1
    if (-not $line) { return "" }
    return ($line -split "=", 2)[1]
}

$apiKey = Get-EnvValue "PROBE_API_KEY"
if ([string]::IsNullOrWhiteSpace($apiKey) -or $apiKey -eq "change-me") {
    $apiKey = New-ApiKey
    Set-EnvValue "PROBE_API_KEY" $apiKey
}

$probePort = Get-EnvValue "PROBE_PORT"
if ([string]::IsNullOrWhiteSpace($probePort)) {
    $probePort = "9443"
    Set-EnvValue "PROBE_PORT" $probePort
}

$publicUrl = Get-EnvValue "PROBE_PUBLIC_URL"
if ([string]::IsNullOrWhiteSpace($publicUrl)) {
    $publicIp = ""
    try {
        $publicIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -Method Get -TimeoutSec 6).ToString()
    } catch {}

    if ([string]::IsNullOrWhiteSpace($publicIp)) {
        $publicUrl = "http://YOUR_VPS_IP:$probePort"
    } else {
        $publicUrl = "http://$publicIp:$probePort"
    }
    Set-EnvValue "PROBE_PUBLIC_URL" $publicUrl
}

$envLines | Set-Content $envFile

Write-Host "Iniciando NetDuo WAN Probe..."
if ($composeCmd -eq "docker compose") {
    docker compose up -d --build | Out-Null
} else {
    docker-compose up -d --build | Out-Null
}

Start-Sleep -Seconds 2
try {
    Invoke-RestMethod -Uri "http://127.0.0.1:$probePort/health" -Method Get -TimeoutSec 8 | Out-Null
} catch {
    Write-Host "No se pudo validar /health local. Revisa logs con $composeCmd logs -f"
}

$payload = @{
    v = 1
    kind = "netduo-wan-probe"
    url = $publicUrl
    apiKey = $apiKey
    createdAt = (Get-Date).ToString("o")
} | ConvertTo-Json -Compress

$token = "NDUO_PROBE_V1:" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd("=").Replace("+", "-").Replace("/", "_")

@"
NETDUO_PROBE_URL=$publicUrl
NETDUO_PROBE_KEY=$apiKey
NETDUO_CONNECT_TOKEN=$token
"@ | Set-Content $outFile

Write-Host ""
Write-Host "==============================================="
Write-Host " NetDuo WAN Probe listo"
Write-Host "==============================================="
Get-Content $outFile
Write-Host "==============================================="
Write-Host "Archivo generado: $Root\\$outFile"
Write-Host ""
Write-Host "Pega NETDUO_CONNECT_TOKEN en la app NetDuo."

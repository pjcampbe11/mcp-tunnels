<#
.SYNOPSIS
    Host-side triage for MCP servers, stdio bridges and reverse tunnels on Windows.

.DESCRIPTION
    Read-only. Safe on production endpoints. No admin required for most checks
    (process owner resolution and some ETW-backed data are better with admin).

    The finding that matters is the CORRELATION at the end: a process holding a
    loopback LISTEN socket while a known tunnel agent holds an outbound
    ESTABLISHED session. Either alone is normal developer noise. Together they
    mean a locally bound service is reachable from the internet without any
    inbound firewall rule having changed.

.EXAMPLE
    .\Find-McpTunnel.ps1
    .\Find-McpTunnel.ps1 -AsJson | Out-File C:\temp\mcp-triage.json
#>
[CmdletBinding()]
param(
    [switch]$AsJson
)

$ErrorActionPreference = 'SilentlyContinue'

$TunnelNames = @('cloudflared','ngrok','lt','localtunnel','tailscaled','tailscale',
                 'frpc','bore','pagekite','devtunnel','ssh','plink')
$BridgePattern = 'mcp-remote|supergateway|mcp-proxy|mcpo|stdio-to-sse'
$ServerPattern = 'mcp|fastmcp|modelcontextprotocol'
$TunnelDomains = @('ngrok.io','ngrok-free.app','ngrok.com','trycloudflare.com',
                   'argotunnel.com','devtunnels.ms','loca.lt','lhr.life',
                   'serveo.net','pagekite.me','ts.net')

$Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param([string]$Category,[hashtable]$Data)
    $o = [ordered]@{
        Host      = $env:COMPUTERNAME
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Category  = $Category
    }
    foreach ($k in $Data.Keys) { $o[$k] = $Data[$k] }
    $Findings.Add([pscustomobject]$o) | Out-Null
}

# --- 1/2. Listening sockets ------------------------------------------------
$listeners = Get-NetTCPConnection -State Listen
foreach ($l in $listeners) {
    $p = Get-Process -Id $l.OwningProcess
    $isLoopback = $l.LocalAddress -in @('127.0.0.1','::1')
    Add-Finding ($(if ($isLoopback) {'LoopbackListener'} else {'RoutableListener'})) @{
        LocalAddress = $l.LocalAddress
        LocalPort    = $l.LocalPort
        Pid          = $l.OwningProcess
        Process      = $p.ProcessName
        Path         = $p.Path
        StartTime    = $p.StartTime
    }
}

# --- 3. Reverse tunnel agents ---------------------------------------------
foreach ($proc in Get-CimInstance Win32_Process) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($proc.Name)
    $cmd  = $proc.CommandLine
    if ($TunnelNames -contains $base -or $cmd -match 'tunnel\s+--url|--authtoken|http\s+\d{2,5}') {
        Add-Finding 'TunnelProcess' @{
            Pid = $proc.ProcessId; Parent = $proc.ParentProcessId
            Name = $proc.Name; CommandLine = $cmd; Path = $proc.ExecutablePath
        }
    }
    if ($cmd -match $BridgePattern) {
        Add-Finding 'McpBridgeProcess' @{
            Pid = $proc.ProcessId; Parent = $proc.ParentProcessId
            Name = $proc.Name; CommandLine = $cmd
        }
    }
    elseif ($cmd -match $ServerPattern -and $cmd -notmatch 'Find-McpTunnel') {
        Add-Finding 'McpServerProcess' @{
            Pid = $proc.ProcessId; Parent = $proc.ParentProcessId
            Name = $proc.Name; CommandLine = $cmd
        }
    }
}

# --- 4. MCP client configuration on disk ----------------------------------
$cfgPaths = @(
    "$env:USERPROFILE\.claude.json",
    "$env:USERPROFILE\.claude\settings.json",
    "$env:USERPROFILE\.claude\mcp.json",
    "$env:APPDATA\Claude\claude_desktop_config.json",
    "$env:USERPROFILE\.cursor\mcp.json",
    "$env:APPDATA\Code\User\mcp.json",
    "$env:USERPROFILE\.codeium\windsurf\mcp_config.json",
    "$env:ProgramData\ClaudeCode\managed-settings.json"
)
foreach ($c in $cfgPaths) {
    if (Test-Path $c) {
        $fi = Get-Item $c
        Add-Finding 'McpConfigFile' @{
            Path = $c; LastWriteUtc = $fi.LastWriteTimeUtc; Bytes = $fi.Length
            Sha256 = (Get-FileHash $c -Algorithm SHA256).Hash
        }
    }
}
# Project-scoped configs arrive with a git clone. Scan common code roots only.
foreach ($root in @("$env:USERPROFILE\source","$env:USERPROFILE\repos","$env:USERPROFILE\git","C:\dev")) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -Depth 4 -Include '.mcp.json','mcp.json' -File |
        ForEach-Object {
            Add-Finding 'McpConfigFile' @{
                Path = $_.FullName; LastWriteUtc = $_.LastWriteTimeUtc; Bytes = $_.Length
            }
        }
    }
}

# --- 5. Outbound sessions owned by tunnel/bridge processes ----------------
$est = Get-NetTCPConnection -State Established
foreach ($c in $est) {
    $p = Get-Process -Id $c.OwningProcess
    if ($p -and ($TunnelNames -contains $p.ProcessName -or $p.ProcessName -match 'node|python|pwsh')) {
        Add-Finding 'OutboundSession' @{
            Process = $p.ProcessName; Pid = $c.OwningProcess
            Remote  = "$($c.RemoteAddress):$($c.RemotePort)"
            Local   = "$($c.LocalAddress):$($c.LocalPort)"
        }
    }
}

# --- 6. Resolver cache evidence of tunnel provider infrastructure ---------
foreach ($e in Get-DnsClientCache) {
    foreach ($d in $TunnelDomains) {
        if ($e.Entry -like "*$d*") {
            Add-Finding 'TunnelDnsCache' @{ Entry = $e.Entry; Data = $e.Data; Type = $e.Type }
        }
    }
}

# --- 7. Correlation --------------------------------------------------------
$loopCount   = ($Findings | Where-Object Category -eq 'LoopbackListener').Count
$tunnelProcs = $Findings | Where-Object Category -eq 'TunnelProcess'
if ($loopCount -gt 0 -and $tunnelProcs.Count -gt 0) {
    Add-Finding 'CORRELATION_HIT' @{
        LoopbackListeners = $loopCount
        TunnelPids        = ($tunnelProcs.Pid -join ',')
        Note = 'Locally bound service may be internet-reachable with no inbound rule change'
    }
} else {
    Add-Finding 'CorrelationClear' @{ LoopbackListeners = $loopCount; TunnelProcesses = $tunnelProcs.Count }
}

# --- Output ----------------------------------------------------------------
if ($AsJson) {
    $Findings | ConvertTo-Json -Depth 5
} else {
    $Findings | Group-Object Category | ForEach-Object {
        Write-Host ""
        Write-Host "=== $($_.Name) ($($_.Count)) ===" -ForegroundColor Cyan
        $_.Group | Format-List | Out-String | Write-Host
    }
}

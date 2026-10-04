#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Bind = '127.0.0.1',
    [ValidateRange(1, 65535)][int]$Port = 8080,
    [ValidateSet('DoH', 'System')][string]$DNS = 'DoH',
    [switch]$Fragment,
    [int[]]$SplitAt = @(1, 6),
    [ValidateRange(0, 2000)][int]$DelayMs = 40,
    [switch]$Test,
    [switch]$VerboseLog,
    [switch]$SetSystemProxy,
    [switch]$ClearSystemProxy
)

$ErrorActionPreference = 'Stop'

$Usage = @'
================================================================
  Start-DoHProxy.ps1 - proxy lokal (DoH resolver + fragmentasi ClientHello)
----------------------------------------------------------------
  Proxy aktif di  : http://127.0.0.1:{0}
  Mode DNS        : {1}
  Fragmentasi     : {2} (split di byte {3}, delay {4} ms)
----------------------------------------------------------------
  Pakai di browser:
    chrome.exe --proxy-server=http://127.0.0.1:{0}
    edge.exe   --proxy-server=http://127.0.0.1:{0}
    Firefox    -> Settings > Network > Manual proxy: 127.0.0.1 port {0}
    Windows    -> pakai -SetSystemProxy (berlaku utk app berbasis WinINET)
  Tes dari terminal:
    curl.exe -x http://127.0.0.1:{0} https://nyaa.si/
  Berhenti: Ctrl+C
================================================================
'@

function Set-SystemProxyState([int]$Port, [bool]$Enable) {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($Enable) {
        New-ItemProperty -Path $key -Name ProxyServer -Value "127.0.0.1:$Port" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name ProxyEnable -Value 1 -PropertyType DWord -Force | Out-Null
    } else {
        New-ItemProperty -Path $key -Name ProxyEnable -Value 0 -PropertyType DWord -Force | Out-Null
    }
    $sig = '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(System.IntPtr h, int dw, System.IntPtr p, int l);'
    $inet = Add-Type -MemberDefinition $sig -Name WinInetOpt -Namespace DoHProxy -PassThru
    $null = $inet::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    $null = $inet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
}

$WorkerCode = @'
param($Client, $Cfg)
$ErrorActionPreference = 'Stop'

function Close-Safe($o) {
    if ($null -ne $o) { try { $o.Close() } catch { } }
}

function Write-Log([string]$m) {
    try { [void]$Cfg.Log.Add(('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $m)) } catch { }
}

function Resolve-Name([string]$Name) {
    if ($Cfg.Cache.ContainsKey($Name)) { return $Cfg.Cache[$Name] }
    $ip = $null
    if ($Cfg.DNS -eq 'DoH') {
        $urls = @(
            'https://dns.google/resolve?name=' + $Name + '&type=A',
            'https://cloudflare-dns.com/dns-query?name=' + $Name + '&type=A'
        )
        foreach ($u in $urls) {
            try {
                $j = Invoke-RestMethod -Uri $u -Headers @{ Accept = 'application/dns-json' } -TimeoutSec 8
                foreach ($a in @($j.Answer)) {
                    if ([int]$a.type -eq 1) { $ip = [string]$a.data; break }
                }
                if ($ip) { break }
            } catch { }
        }
    }
    if (-not $ip) {
        try {
            foreach ($x in @([Net.Dns]::GetHostAddresses($Name))) {
                if ($x.AddressFamily -eq 'InterNetwork') { $ip = $x.IPAddressToString; break }
            }
        } catch { }
    }
    if ($ip) { $Cfg.Cache[$Name] = $ip }
    return $ip
}

function Read-Head($s) {
    $old = -1
    try { $old = $s.ReadTimeout } catch { }
    try { $s.ReadTimeout = 20000 } catch { }
    $ms = New-Object System.IO.MemoryStream
    $buf = New-Object byte[] 8192
    try {
        while ($true) {
            if ($ms.Length -gt 131072) { return $null }
            $n = $s.Read($buf, 0, $buf.Length)
            if ($n -le 0) { return $null }
            $ms.Write($buf, 0, $n)
            $arr = $ms.ToArray()
            for ($i = 0; $i -le $arr.Length - 4; $i++) {
                if ($arr[$i] -eq 13 -and $arr[$i + 1] -eq 10 -and $arr[$i + 2] -eq 13 -and $arr[$i + 3] -eq 10) {
                    $hl = $i + 4
                    $extra = New-Object byte[] ($arr.Length - $hl)
                    [Array]::Copy($arr, $hl, $extra, 0, $extra.Length)
                    return @{
                        Head  = [Text.Encoding]::ASCII.GetString($arr, 0, $hl)
                        Bytes = $arr
                        Extra = $extra
                    }
                }
            }
        }
    } catch { return $null }
    finally { try { if ($old -ge 0) { $s.ReadTimeout = $old } } catch { } }
}

function Send-Fragmented($s, [byte[]]$data, [int[]]$cuts, [int]$delay) {
    $points = @()
    foreach ($c in $cuts) { if ($c -gt 0 -and $c -lt $data.Length) { $points += $c } }
    $points = @($points | Sort-Object -Unique)
    $start = 0
    foreach ($p in $points) {
        $len = $p - $start
        if ($len -gt 0) {
            $s.Write($data, $start, $len)
            $s.Flush()
            if ($delay -gt 0) { Start-Sleep -Milliseconds $delay }
        }
        $start = $p
    }
    if ($start -lt $data.Length) {
        $s.Write($data, $start, $data.Length - $start)
        $s.Flush()
    }
}

function Invoke-Relay($a, $b) {
    $as = $a.GetStream()
    $bs = $b.GetStream()
    $buf = New-Object byte[] 65536
    while ($a.Connected -and $b.Connected) {
        $busy = $false
        try {
            if ($as.DataAvailable) {
                $n = $as.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                $bs.Write($buf, 0, $n)
                $bs.Flush()
                $busy = $true
            }
            if ($bs.DataAvailable) {
                $n = $bs.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                $as.Write($buf, 0, $n)
                $as.Flush()
                $busy = $true
            }
        } catch { break }
        if (-not $busy) { Start-Sleep -Milliseconds 5 }
    }
}

$remote = $null
try {
    $Client.NoDelay = $true
    $ns = $Client.GetStream()
    $head = Read-Head $ns
    if (-not $head) { return }

    $firstLine = ($head.Head -split "`r`n")[0]
    $isConnect = $firstLine -match '^CONNECT\s+(?<h>[^:\s]+):(?<p>\d+)'
    if ($isConnect) {
        $name = $Matches['h']
        $targetPort = [int]$Matches['p']
    } elseif ($firstLine -match '^[A-Z]+\s+(?:https?://)(?<h>[^/:]+)(?::(?<p>\d+))?') {
        $name = $Matches['h']
        $targetPort = if ($Matches['p']) { [int]$Matches['p'] } else { 80 }
    } else {
        Write-Log ("tolak: {0}" -f $firstLine)
        return
    }

    $ip = Resolve-Name $name
    if (-not $ip) {
        Write-Log ("gagal-resolve: {0}" -f $name)
        return
    }

    $remote = New-Object Net.Sockets.TcpClient
    $remote.NoDelay = $true
    $remote.Connect($ip, $targetPort)
    $rs = $remote.GetStream()
    Write-Log ("{0} -> {1}:{2}" -f $name, $ip, $targetPort)

    if ($isConnect) {
        $ok = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection Established`r`n`r`n")
        $ns.Write($ok, 0, $ok.Length)
        $ns.Flush()
        $buf = New-Object byte[] 65536
        try { $ns.ReadTimeout = 20000 } catch { }
        $n = $ns.Read($buf, 0, $buf.Length)
        if ($n -gt 0) {
            $firstPayload = New-Object byte[] $n
            [Array]::Copy($buf, $firstPayload, $n)
            if ($Cfg.Fragment) {
                Send-Fragmented $rs $firstPayload $Cfg.SplitAt $Cfg.DelayMs
                Write-Log ("{0}: clienthello dipecah {1} segmen" -f $name, (@($Cfg.SplitAt).Count + 1))
            } else {
                $rs.Write($firstPayload, 0, $firstPayload.Length)
                $rs.Flush()
            }
        }
    } else {
        $rs.Write($head.Bytes, 0, $head.Bytes.Length)
        $rs.Flush()
    }

    Invoke-Relay $Client $remote
} catch {
    Write-Log ("error: {0}" -f $_.Exception.Message)
} finally {
    Close-Safe $remote
    Close-Safe $Client
}
'@

$AcceptCode = @'
param($Listener, $Worker, $Pool, $Cfg)
$jobs = New-Object System.Collections.ArrayList
while ($true) {
    try { $client = $Listener.AcceptTcpClient() } catch { break }
    for ($i = $jobs.Count - 1; $i -ge 0; $i--) {
        if ($jobs[$i].Handle.IsCompleted) { $jobs[$i].PS.Dispose(); $jobs.RemoveAt($i) }
    }
    $ps = [powershell]::Create()
    $ps.RunspacePool = $Pool
    $null = $ps.AddScript($Worker).AddArgument($client).AddArgument($Cfg)
    [void]$jobs.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
}
'@

function Invoke-LoopbackTest([int]$ProxyPort) {
    $tcp = New-Object Net.Sockets.TcpClient
    $tcp.Connect([Net.IPAddress]::Loopback, $ProxyPort)
    $s = $tcp.GetStream()
    $req = "CONNECT nyaa.si:443 HTTP/1.1`r`nHost: nyaa.si:443`r`n`r`n"
    $b = [Text.Encoding]::ASCII.GetBytes($req)
    $s.Write($b, 0, $b.Length)
    $s.Flush()
    $buf = New-Object byte[] 4096
    $n = $s.Read($buf, 0, $buf.Length)
    $resp = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
    if ($resp -notmatch '^HTTP/1\.[01] 200') {
        Write-Host "PROXY GAGAL: $resp" -ForegroundColor Red
        return
    }
    $ssl = New-Object Net.Security.SslStream($s, $false)
    try {
        $ssl.AuthenticateAsClient('nyaa.si')
        Write-Host ("SERTIFIKAT : {0}" -f $ssl.RemoteCertificate.Subject) -ForegroundColor Green
        Write-Host ("ISSUER      : {0}" -f $ssl.RemoteCertificate.Issuer) -ForegroundColor Green
    } catch {
        Write-Host ("TLS GAGAL   : {0}" -f $_.Exception.Message) -ForegroundColor Red
        return
    }
    $g = "GET / HTTP/1.1`r`nHost: nyaa.si`r`nUser-Agent: doh-proxy-test`r`nConnection: close`r`n`r`n"
    $b = [Text.Encoding]::ASCII.GetBytes($g)
    $ssl.Write($b, 0, $b.Length)
    $ssl.Flush()
    $ms = New-Object IO.MemoryStream
    while (($n = $ssl.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n) }
    $t = [Text.Encoding]::UTF8.GetString($ms.ToArray())
    if ($t -match '<title>([^<]+)</title>') {
        Write-Host ("HALAMAN     : {0}" -f $Matches[1]) -ForegroundColor Green
    } else {
        Write-Host ("AWAL        : {0}" -f (($t -split "`r?`n") | Select-Object -First 3)) -ForegroundColor Yellow
    }
    $ssl.Close()
    $tcp.Close()
}

$cfg = @{
    DNS      = $DNS
    Fragment = [bool]$Fragment
    SplitAt  = $SplitAt
    DelayMs  = $DelayMs
    Log      = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    Cache    = [hashtable]::Synchronized(@{})
}

if ($SetSystemProxy) { Set-SystemProxyState -Port $Port -Enable $true }
if ($ClearSystemProxy) { Set-SystemProxyState -Port $Port -Enable $false }

$pool = [runspacefactory]::CreateRunspacePool(1, 32)
$pool.Open()
$listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Parse($Bind), $Port)
$listener.Start()

$accept = [powershell]::Create()
$accept.RunspacePool = $pool
$null = $accept.AddScript($AcceptCode).AddArgument($listener).AddArgument($WorkerCode).AddArgument($pool).AddArgument($cfg)
$acceptHandle = $accept.BeginInvoke()

try {
    Write-Host ($Usage -f $Port, $DNS, $Fragment, ($SplitAt -join ','), $DelayMs) -ForegroundColor Cyan

    if ($Test) {
        Start-Sleep -Milliseconds 800
        Invoke-LoopbackTest -ProxyPort $Port
        Start-Sleep -Milliseconds 300
        Write-Host "`nLOG PROXY:" -ForegroundColor Cyan
        foreach ($l in @($cfg.Log)) { Write-Host "  $l" }
    } else {
        if ($SetSystemProxy) { Write-Host "System proxy AKTIF -> 127.0.0.1:$Port" -ForegroundColor Green }
        if ($ClearSystemProxy) { Write-Host "System proxy DIMATIKAN" -ForegroundColor Green }
        if ($VerboseLog) {
            [Console]::Out.WriteLine(('[{0}] listen {1}:{2} dns={3} fragment={4} split={5} delay={6}ms' -f `
                (Get-Date -Format 'HH:mm:ss'), $Bind, $Port, $DNS, $Fragment, ($SplitAt -join ','), $DelayMs))
            $shown = 0
            while ($true) {
                $logs = @($cfg.Log)
                for ($i = $shown; $i -lt $logs.Count; $i++) { [Console]::Out.WriteLine($logs[$i]) }
                $shown = $logs.Count
                Start-Sleep -Milliseconds 300
            }
        } else {
            $null = Read-Host "Tekan Enter untuk berhenti"
        }
    }
} finally {
    try { $listener.Stop() } catch { }
    try { $accept.Stop() } catch { }
    try { $accept.Dispose() } catch { }
    try { $pool.Close() } catch { }
}

<#
.SYNOPSIS
    DNS Watchdog (Windows) - monitors this machine's traffic for signs of DNS poisoning.

.DESCRIPTION
    Uses pktmon.exe - the packet-capture tool built into Windows 10 (1809+),
    Windows 11, and Windows Server 2019+ - to capture DNS traffic (UDP/TCP port 53)
    across every network adapter on this host, which covers both LAN and WAN traffic
    on a typical machine. No third-party capture tool (Wireshark, Npcap, tcpdump) is
    required.

    Detects, in real time:
      1. Conflicting answers to the same DNS query (classic poisoning "race" pattern)
      2. DNS responses from a server this machine never configured/asked
      3. DNS responses with no matching outstanding query
      4. Changes to the default gateway's MAC address (ARP-spoofing precursor to
         on-LAN DNS poisoning)

    Every alert prints a [TECHNICAL] line (raw packet detail) and a
    [WHAT THIS MEANS] line (plain-language explanation), and is written to a log file.

.PARAMETER LogFile
    Path to the session log file. Defaults to .\dns_watchdog_<timestamp>.log

.PARAMETER CaptureIntervalSeconds
    How long each capture window runs before being converted and analyzed.
    Smaller values mean lower detection latency but more overhead. Default: 5.

.PARAMETER GraceResponses
    Number of responses to observe before "response with no matching query"
    alerts are enabled, to avoid noise at startup. Default: 10.

.PARAMETER KeepCaptures
    If set, .etl/.pcapng files for each capture window are kept on disk instead
    of being deleted after analysis.

.EXAMPLE
    .\dns_watchdog.ps1
    Run with defaults (must be started from an elevated/Administrator PowerShell).

.EXAMPLE
    .\dns_watchdog.ps1 -LogFile C:\logs\dns.log -CaptureIntervalSeconds 3
#>

[CmdletBinding()]
param(
    [string]$LogFile = ".\dns_watchdog_$(Get-Date -Format yyyyMMdd_HHmmss).log",
    [int]$CaptureIntervalSeconds = 5,
    [int]$GraceResponses = 10,
    [switch]$KeepCaptures
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script needs to run in an elevated (Administrator) PowerShell session, because pktmon requires it for packet capture."
    exit 1
}

if (-not (Get-Command pktmon.exe -ErrorAction SilentlyContinue)) {
    Write-Error "pktmon.exe was not found. It ships with Windows 10 1809+ / Windows 11 / Windows Server 2019+. If you're on an older build, this script cannot run natively."
    exit 1
}

# ---------------------------------------------------------------------------
# Discovery: default route interface, gateway, gateway MAC, configured DNS
# ---------------------------------------------------------------------------

function Get-DefaultRouteInfo {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object -Property RouteMetric |
        Select-Object -First 1
    if (-not $route) { return $null }
    return [PSCustomObject]@{
        Gateway        = $route.NextHop
        InterfaceIndex = $route.InterfaceIndex
        InterfaceAlias = $route.InterfaceAlias
    }
}

function Get-GatewayMac {
    param([string]$Gateway)
    try {
        Test-Connection -ComputerName $Gateway -Count 1 -Quiet -ErrorAction SilentlyContinue | Out-Null
    } catch {}
    $n = Get-NetNeighbor -IPAddress $Gateway -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne 'Unreachable' } |
        Select-Object -First 1
    if ($n) { return $n.LinkLayerAddress }
    return $null
}

function Get-ConfiguredDnsServers {
    $servers = Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty ServerAddresses |
        Where-Object { $_ -and $_ -ne '0.0.0.0' } |
        Sort-Object -Unique
    return $servers
}

$routeInfo = Get-DefaultRouteInfo
if (-not $routeInfo) {
    Write-Error "Could not determine a default route / gateway on this machine."
    exit 1
}

$Gateway = $routeInfo.Gateway
$GatewayMacBaseline = Get-GatewayMac -Gateway $Gateway
$ExpectedDnsServers = @(Get-ConfiguredDnsServers)

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

function Write-Line {
    param([string]$Text)
    Write-Host $Text
    Add-Content -Path $LogFile -Value $Text
}

Write-Line "========================================================================="
Write-Line " DNS Watchdog (Windows) - DNS poisoning / spoofing monitor"
Write-Line "========================================================================="
Write-Line "Capturing on:      all network adapters (pktmon captures at the OS networking stack,"
Write-Line "                   which covers this host's LAN and WAN traffic together)"
Write-Line "Default gateway:   $Gateway  (MAC baseline: $(if ($GatewayMacBaseline) { $GatewayMacBaseline } else { 'unknown' }))"
Write-Line "Configured DNS:    $(if ($ExpectedDnsServers.Count -gt 0) { $ExpectedDnsServers -join ', ' } else { 'none detected' })"
Write-Line "Log file:          $LogFile"
Write-Line ""
Write-Line "What this does, in plain terms:"
Write-Line "  Every time this machine looks up a website's address, it sends a DNS"
Write-Line "  question and gets a DNS answer back. This tool captures that traffic in"
Write-Line "  short windows using pktmon (Windows' built-in packet capture tool) and"
Write-Line "  flags patterns that don't happen during normal, honest DNS activity -"
Write-Line "  such as getting two different answers to the same question, or an"
Write-Line "  answer from a server you never asked. It also watches whether your"
Write-Line "  router's hardware (MAC) address suddenly changes, which is how attackers"
Write-Line "  commonly position themselves to tamper with DNS on a LAN."
Write-Line ""
Write-Line "Each alert has two parts:"
Write-Line "  [TECHNICAL]       - the raw packet detail, for someone investigating"
Write-Line "  [WHAT THIS MEANS] - a plain-language explanation of why it matters"
Write-Line ""
Write-Line "Press Ctrl+C to stop. A summary prints when you do."
Write-Line "========================================================================="

# ---------------------------------------------------------------------------
# pktmon capture filter
# ---------------------------------------------------------------------------

pktmon filter remove | Out-Null
pktmon filter add -p 53 | Out-Null

$TempDir = Join-Path $env:TEMP "dns_watchdog_$PID"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

# ---------------------------------------------------------------------------
# pcapng + DNS parsing
# ---------------------------------------------------------------------------

function Get-PcapngPackets {
    param([string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $len = $bytes.Length
    $pos = 0
    $packets = New-Object System.Collections.Generic.List[object]

    while ($pos + 8 -le $len) {
        $blockType = [BitConverter]::ToUInt32($bytes, $pos)
        $blockTotalLen = [BitConverter]::ToUInt32($bytes, $pos + 4)
        if ($blockTotalLen -lt 12 -or ($pos + $blockTotalLen) -gt $len) { break }

        if ($blockType -eq 0x00000006) {
            $bodyOffset = $pos + 8
            $capLen = [BitConverter]::ToUInt32($bytes, $bodyOffset + 12)
            $dataOffset = $bodyOffset + 20
            if ($dataOffset + $capLen -le $len) {
                $frame = New-Object byte[] $capLen
                [Array]::Copy($bytes, $dataOffset, $frame, 0, $capLen)
                $packets.Add($frame)
            }
        }
        $pos += $blockTotalLen
    }
    return $packets
}

function Read-DnsName {
    param([byte[]]$Bytes, [int]$Pos, [int]$MsgBase)

    $labels = New-Object System.Collections.Generic.List[string]
    $jumped = $false
    $safety = 0
    $curPos = $Pos
    $returnPos = -1

    while ($true) {
        $safety++
        if ($safety -gt 128 -or $curPos -ge $Bytes.Length) { break }
        $lenByte = $Bytes[$curPos]
        if ($lenByte -eq 0) {
            if (-not $jumped) { $returnPos = $curPos + 1 }
            break
        }
        elseif (($lenByte -band 0xC0) -eq 0xC0) {
            if ($curPos + 1 -ge $Bytes.Length) { break }
            $ptr = (([int]$lenByte -band 0x3F) -shl 8) -bor [int]$Bytes[$curPos + 1]
            if (-not $jumped) { $returnPos = $curPos + 2 }
            $jumped = $true
            $curPos = $MsgBase + $ptr
            continue
        }
        else {
            $start = $curPos + 1
            if ($start + $lenByte -gt $Bytes.Length) { break }
            $labels.Add([System.Text.Encoding]::ASCII.GetString($Bytes, $start, $lenByte))
            $curPos = $start + $lenByte
        }
    }

    if ($returnPos -eq -1) { $returnPos = $curPos }
    return @{ Name = ($labels -join '.'); NextPos = $returnPos }
}

function Parse-DnsMessage {
    param([byte[]]$Bytes, [int]$Base)

    if ($Base + 12 -gt $Bytes.Length) { return $null }

    $id      = ([int]$Bytes[$Base] -shl 8) -bor [int]$Bytes[$Base+1]
    $flags   = ([int]$Bytes[$Base+2] -shl 8) -bor [int]$Bytes[$Base+3]
    $qr      = ($flags -shr 15) -band 1
    $qdcount = ([int]$Bytes[$Base+4] -shl 8) -bor [int]$Bytes[$Base+5]
    $ancount = ([int]$Bytes[$Base+6] -shl 8) -bor [int]$Bytes[$Base+7]

    $pos = $Base + 12
    $qName = ""; $qType = 0
    for ($i = 0; $i -lt $qdcount; $i++) {
        $r = Read-DnsName -Bytes $Bytes -Pos $pos -MsgBase $Base
        $pos = $r.NextPos
        if ($pos + 4 -gt $Bytes.Length) { return $null }
        if ($i -eq 0) {
            $qName = $r.Name
            $qType = ([int]$Bytes[$pos] -shl 8) -bor [int]$Bytes[$pos+1]
        }
        $pos += 4
    }

    $answers = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $ancount; $i++) {
        if ($pos -ge $Bytes.Length) { break }
        $r = Read-DnsName -Bytes $Bytes -Pos $pos -MsgBase $Base
        $pos = $r.NextPos
        if ($pos + 10 -gt $Bytes.Length) { break }
        $rtype = ([int]$Bytes[$pos] -shl 8) -bor [int]$Bytes[$pos+1]
        $rdlen = ([int]$Bytes[$pos+8] -shl 8) -bor [int]$Bytes[$pos+9]
        $rdataStart = $pos + 10
        $val = "(type $rtype)"
        if ($rtype -eq 1 -and $rdlen -eq 4 -and ($rdataStart + 4) -le $Bytes.Length) {
            $val = "A:{0}.{1}.{2}.{3}" -f $Bytes[$rdataStart], $Bytes[$rdataStart+1], $Bytes[$rdataStart+2], $Bytes[$rdataStart+3]
        }
        elseif ($rtype -eq 28 -and $rdlen -eq 16 -and ($rdataStart + 16) -le $Bytes.Length) {
            $parts = for ($j = 0; $j -lt 16; $j += 2) { "{0:x2}{1:x2}" -f $Bytes[$rdataStart+$j], $Bytes[$rdataStart+$j+1] }
            $val = "AAAA:" + ($parts -join ':')
        }
        $answers.Add($val)
        $pos = $rdataStart + $rdlen
    }

    return [PSCustomObject]@{
        TxnId      = $id
        IsResponse = ($qr -eq 1)
        Question   = $qName
        QType      = $qType
        Answers    = @($answers)
    }
}

function Parse-EthernetFrame {
    param([byte[]]$Frame)

    if ($Frame.Length -lt 14) { return $null }

    # pktmon captures packets at multiple points in the Windows network stack.
    # Inbound packets are usually already Ethernet-framed by the time they're
    # captured. Outbound (locally-generated) packets are frequently captured
    # BEFORE the Ethernet header is added, so they arrive here as a raw IP
    # packet starting at offset 0. Try Ethernet framing first (a real EtherType
    # match is essentially unambiguous); only if that fails, try interpreting
    # the frame as a bare IPv4/IPv6 packet with no link-layer header at all.
    $ethType = ([int]$Frame[12] -shl 8) -bor [int]$Frame[13]
    $offset = 14
    $isEthernet = $true
    if ($ethType -eq 0x8100) {
        if ($Frame.Length -lt 18) { return $null }
        $ethType = ([int]$Frame[16] -shl 8) -bor [int]$Frame[17]
        $offset = 18
    }
    elseif ($ethType -ne 0x0800 -and $ethType -ne 0x86DD) {
        $isEthernet = $false
    }

    if (-not $isEthernet) {
        $topNibble = ($Frame[0] -band 0xF0) -shr 4
        if ($topNibble -eq 4) { $ethType = 0x0800; $offset = 0 }
        elseif ($topNibble -eq 6) { $ethType = 0x86DD; $offset = 0 }
        else { return $null }
    }

    $srcIp = $null; $dstIp = $null; $proto = $null; $ipHeaderLen = 0

    if ($ethType -eq 0x0800) {
        if ($Frame.Length -lt $offset + 20) { return $null }
        $ihl = ($Frame[$offset] -band 0x0F) * 4
        $proto = $Frame[$offset + 9]
        $srcIp = "{0}.{1}.{2}.{3}" -f $Frame[$offset+12], $Frame[$offset+13], $Frame[$offset+14], $Frame[$offset+15]
        $dstIp = "{0}.{1}.{2}.{3}" -f $Frame[$offset+16], $Frame[$offset+17], $Frame[$offset+18], $Frame[$offset+19]
        $ipHeaderLen = $ihl
    }
    elseif ($ethType -eq 0x86DD) {
        if ($Frame.Length -lt $offset + 40) { return $null }
        $proto = $Frame[$offset + 6]
        $srcParts = for ($j = 0; $j -lt 16; $j += 2) { "{0:x2}{1:x2}" -f $Frame[$offset+8+$j], $Frame[$offset+8+$j+1] }
        $dstParts = for ($j = 0; $j -lt 16; $j += 2) { "{0:x2}{1:x2}" -f $Frame[$offset+24+$j], $Frame[$offset+24+$j+1] }
        $srcIp = ($srcParts -join ':')
        $dstIp = ($dstParts -join ':')
        $ipHeaderLen = 40
    }
    else { return $null }

    $l4Offset = $offset + $ipHeaderLen
    $srcPort = $null; $dstPort = $null; $dnsOffset = $null; $protoName = $null

    if ($proto -eq 17) {
        if ($Frame.Length -lt $l4Offset + 8) { return $null }
        $srcPort = ([int]$Frame[$l4Offset] -shl 8) -bor [int]$Frame[$l4Offset+1]
        $dstPort = ([int]$Frame[$l4Offset+2] -shl 8) -bor [int]$Frame[$l4Offset+3]
        $dnsOffset = $l4Offset + 8
        $protoName = "UDP"
    }
    elseif ($proto -eq 6) {
        if ($Frame.Length -lt $l4Offset + 20) { return $null }
        $srcPort = ([int]$Frame[$l4Offset] -shl 8) -bor [int]$Frame[$l4Offset+1]
        $dstPort = ([int]$Frame[$l4Offset+2] -shl 8) -bor [int]$Frame[$l4Offset+3]
        $tcpHeaderLen = (($Frame[$l4Offset + 12] -band 0xF0) -shr 4) * 4
        $payloadOffset = $l4Offset + $tcpHeaderLen
        # DNS-over-TCP carries a 2-byte length prefix before the message.
        # Segments spanning multiple TCP packets are not reassembled here (see README).
        if ($Frame.Length -lt $payloadOffset + 2) { return $null }
        $dnsOffset = $payloadOffset + 2
        $protoName = "TCP"
    }
    else { return $null }

    if ($srcPort -ne 53 -and $dstPort -ne 53) { return $null }
    if ($dnsOffset -ge $Frame.Length) { return $null }

    return [PSCustomObject]@{
        SrcIp = $srcIp; DstIp = $dstIp; SrcPort = $srcPort; DstPort = $dstPort
        Proto = $protoName; DnsOffset = $dnsOffset
    }
}

# ---------------------------------------------------------------------------
# Detection state (persists across capture windows for the life of the process)
# ---------------------------------------------------------------------------

$QuerySeen   = @{}   # txnid -> $true
$QueryData   = @{}   # txnid -> "name/type" string, for display
$ResponseData = @{}  # txnid -> first response's answer signature seen
$ResponseCount = @{} # txnid -> count of responses seen
$Stats = [PSCustomObject]@{ Queries = 0; Responses = 0; Alerts = 0 }
$ExpectedSet = @{}
foreach ($s in $ExpectedDnsServers) { $ExpectedSet[$s] = $true }

function Write-Alert {
    param([string]$Title, [string]$Technical, [string]$Explanation)
    $ts = Get-Date -Format "HH:mm:ss.fff"
    $Stats.Alerts++
    Write-Line ""
    Write-Line "[$ts] [ALERT] $Title"
    Write-Line "  [TECHNICAL] $Technical"
    Write-Line "  [WHAT THIS MEANS] $Explanation"
}

$script:SeenThisWindow = New-Object System.Collections.Generic.HashSet[string]

function Process-DnsPacket {
    param($Eth, $Dns)

    $answerSig = ($Dns.Answers -join ', ')

    # pktmon frequently reports the exact same physical packet more than once
    # (captured at different points in the network stack). Suppress byte-for-byte
    # repeats of the same query/response within this capture window so one real
    # packet doesn't get processed - and potentially alerted on - multiple times.
    # A genuinely conflicting/poisoned response has DIFFERENT answer content, so
    # it is never suppressed by this check.
    $dedupKey = "$($Eth.SrcIp)|$($Eth.SrcPort)|$($Eth.DstIp)|$($Eth.DstPort)|$($Dns.TxnId)|$($Dns.IsResponse)|$answerSig"
    if (-not $script:SeenThisWindow.Add($dedupKey)) { return }

    if (-not $Dns.IsResponse) {
        $Stats.Queries++
        $QuerySeen[$Dns.TxnId] = $true
        $QueryData[$Dns.TxnId] = "$($Dns.Question) (type $($Dns.QType))"
        return
    }

    $Stats.Responses++
    $already = 0
    if ($ResponseCount.ContainsKey($Dns.TxnId)) { $already = $ResponseCount[$Dns.TxnId] }
    $ResponseCount[$Dns.TxnId] = $already + 1

    if ($ExpectedSet.Count -gt 0 -and -not $ExpectedSet.ContainsKey($Eth.SrcIp)) {
        Write-Alert -Title "Unexpected DNS server responded" `
            -Technical "txn=$($Dns.TxnId)  src=$($Eth.SrcIp)  dst=$($Eth.DstIp)  answers=[$answerSig]  (expected one of: $($ExpectedDnsServers -join ', '))" `
            -Explanation "This machine received a DNS answer from a server it wasn't configured to ask ($($Eth.SrcIp)). This can be benign (a VPN, a secondary resolver, split-horizon DNS), but it is also how off-path DNS spoofing presents itself. If $($Eth.SrcIp) isn't a server you recognize, investigate."
    }

    if ($already -ge 1) {
        if ($ResponseData[$Dns.TxnId] -ne $answerSig) {
            $queryLabel = if ($QueryData.ContainsKey($Dns.TxnId)) { $QueryData[$Dns.TxnId] } else { "(unknown)" }
            Write-Alert -Title "Conflicting DNS responses for the same query" `
                -Technical "txn=$($Dns.TxnId)  query=$queryLabel  first_response=[$($ResponseData[$Dns.TxnId])]  conflicting_response(src=$($Eth.SrcIp))=[$answerSig]" `
                -Explanation "This machine's DNS question got two DIFFERENT answers back. Legitimate DNS servers don't normally do this. This is the textbook signature of a DNS poisoning attempt, where an attacker races a forged answer against the real one, hoping the forged one arrives first and gets cached."
        }
    } else {
        $ResponseData[$Dns.TxnId] = $answerSig
    }

    if (-not $QuerySeen.ContainsKey($Dns.TxnId) -and $Stats.Responses -gt $GraceResponses) {
        Write-Alert -Title "DNS response with no matching outstanding query" `
            -Technical "txn=$($Dns.TxnId)  src=$($Eth.SrcIp)  answers=[$answerSig]" `
            -Explanation "An answer arrived for a question this monitor never saw this machine ask. Occasionally that's just a query sent right before monitoring started, but repeated occurrences can indicate injected or spoofed DNS traffic on the network."
    }
}

# ---------------------------------------------------------------------------
# Gateway MAC watch (checked once per capture-loop iteration)
# ---------------------------------------------------------------------------

$script:LastGatewayMac = $GatewayMacBaseline

function Check-GatewayMac {
    if (-not $Gateway -or -not $script:LastGatewayMac) { return }
    $current = Get-GatewayMac -Gateway $Gateway
    if ($current -and $current -ne $script:LastGatewayMac) {
        Write-Alert -Title "Default gateway MAC address changed" `
            -Technical "gateway=$Gateway  baseline_mac=$($script:LastGatewayMac)  new_mac=$current" `
            -Explanation "The hardware address answering for your router just changed. On most home or office networks this almost never happens by itself. It is the classic sign of ARP spoofing - attackers use it on a local network to insert themselves between you and your router, which is often the first step before rewriting DNS answers. If you did not just switch networks or replace your router, investigate immediately."
        $script:LastGatewayMac = $current
    }
}

# ---------------------------------------------------------------------------
# Main capture loop
# ---------------------------------------------------------------------------

$counter = 0

function Show-Summary {
    Write-Line ""
    Write-Line "=== DNS Watchdog session summary ==="
    Write-Line "Queries observed:   $($Stats.Queries)"
    Write-Line "Responses observed: $($Stats.Responses)"
    Write-Line "Alerts raised:      $($Stats.Alerts)"
    if ($Stats.Alerts -eq 0) {
        Write-Line "No signs of DNS poisoning were observed during this session."
    } else {
        Write-Line "Review the [ALERT] lines above. Repeated or clustered alerts are far more meaningful than a single isolated one - an occasional lone alert can be a false positive from network reconfiguration, VPN changes, or multi-answer CDN responses."
    }
}

try {
    while ($true) {
        Check-GatewayMac

        $counter++
        $etl = Join-Path $TempDir "cap_$counter.etl"
        $pcap = Join-Path $TempDir "cap_$counter.pcapng"

        pktmon start --etw --file-name $etl --pkt-size 0 | Out-Null
        Start-Sleep -Seconds $CaptureIntervalSeconds
        pktmon stop | Out-Null

        if (Test-Path $etl) {
            try {
                pktmon pcapng $etl -o $pcap 2>$null | Out-Null
            } catch {
                Write-Line "NOTE: 'pktmon pcapng' conversion failed. This subcommand requires a recent Windows 10/11 build. See README for details."
            }

            if (Test-Path $pcap) {
                $script:SeenThisWindow.Clear()
                $frames = Get-PcapngPackets -Path $pcap
                foreach ($frame in $frames) {
                    try {
                        $eth = Parse-EthernetFrame -Frame $frame
                        if ($null -eq $eth) { continue }
                        $dns = Parse-DnsMessage -Bytes $frame -Base $eth.DnsOffset
                        if ($null -eq $dns) { continue }
                        Process-DnsPacket -Eth $eth -Dns $dns
                    } catch {
                        # Never let one malformed packet stop the monitor.
                        continue
                    }
                }
            }

            if (-not $KeepCaptures) {
                Remove-Item -Path $etl, $pcap -ErrorAction SilentlyContinue
            }
        }
    }
}
finally {
    pktmon stop 2>$null | Out-Null
    pktmon filter remove | Out-Null
    if (-not $KeepCaptures) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Show-Summary
}

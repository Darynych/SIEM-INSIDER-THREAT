# Run INSIDE the Windows client VM (WinDev2407Eval) as Administrator.
# Points the host-only NIC at the DC for DNS and joins lab.local. Reboots at the end.

param(
    [string]$DcIp       = "192.168.56.20",
    [string]$DomainName = "lab.local",
    [string]$NewName    = "WS01"
)

$ErrorActionPreference = "Stop"

# Same NIC logic as the DC: default route = NAT, the other adapter = lab network
$natIf = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
$labIf = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.ifIndex -ne $natIf } | Select-Object -First 1).ifIndex

# Domain DNS must be the DC on both NICs, otherwise the join (and Kerberos) fails
Set-DnsClientServerAddress -InterfaceIndex $labIf -ServerAddresses $DcIp
Set-DnsClientServerAddress -InterfaceIndex $natIf -ServerAddresses $DcIp

if (-not (Resolve-DnsName "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -ErrorAction SilentlyContinue)) {
    throw "Can't find the DC via DNS. Is DC01 running and reachable at $DcIp?"
}

$cred = Get-Credential -Message "Domain admin to join $DomainName" -UserName "LAB\Administrator"
if ($env:COMPUTERNAME -ne $NewName) {
    Add-Computer -DomainName $DomainName -NewName $NewName -Credential $cred -Restart
} else {
    Add-Computer -DomainName $DomainName -Credential $cred -Restart
}

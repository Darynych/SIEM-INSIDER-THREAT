# Run INSIDE DC01, elevated PowerShell. Sets a static lab IP, then promotes a new forest "lab.local".
# The VM reboots at the end; log back in as LAB\Administrator and run 03-populate-ad.ps1.

param(
    [string]$DcIp       = "192.168.56.20",
    [int]$PrefixLength  = 24,
    [string]$DomainName = "lab.local",
    [string]$NetBios    = "LAB",
    [string]$TimeZone   = "GMT Standard Time"   # UK time, so "off-hours" detections line up with your clock
)

$ErrorActionPreference = "Stop"
Set-TimeZone -Id $TimeZone

# NIC with the default route = VirtualBox NAT (internet). The other one = host-only lab network.
$natIf = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
$labIf = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.ifIndex -ne $natIf } | Select-Object -First 1).ifIndex
if (-not $labIf) { throw "Could not find the host-only adapter. Check NIC2 is attached to 'VirtualBox Host-Only Ethernet Adapter'." }

Get-NetAdapter -InterfaceIndex $natIf | Rename-NetAdapter -NewName "NAT"
Get-NetAdapter -InterfaceIndex $labIf | Rename-NetAdapter -NewName "LAB"

Set-NetIPInterface -InterfaceAlias "LAB" -Dhcp Disabled
Get-NetIPAddress -InterfaceAlias "LAB" -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
New-NetIPAddress -InterfaceAlias "LAB" -IPAddress $DcIp -PrefixLength $PrefixLength | Out-Null

# The DC is its own DNS server; don't let it register the NAT address (10.0.2.15) in DNS.
Set-DnsClientServerAddress -InterfaceAlias "LAB" -ServerAddresses "127.0.0.1"
Set-DnsClientServerAddress -InterfaceAlias "NAT" -ServerAddresses "127.0.0.1"
Set-DnsClient -InterfaceAlias "NAT" -RegisterThisConnectionsAddress $false

Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools

$dsrm = Read-Host "DSRM (directory restore) password" -AsSecureString
Install-ADDSForest -DomainName $DomainName -DomainNetbiosName $NetBios `
    -InstallDns -SafeModeAdministratorPassword $dsrm -Force   # reboots automatically

# Run INSIDE DC01 as LAB\Administrator after the promotion reboot.
# Builds OUs, users, groups, the least-privilege n8n service account, OpenSSH, and DNS forwarding.

$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory

$domainDn = (Get-ADDomain).DistinguishedName      # DC=lab,DC=local
$labOu    = "OU=Lab,$domainDn"

# --- NAT DNS: forward external lookups so the DC (and joined clients) still reach the internet
Add-DnsServerForwarder -IPAddress 8.8.8.8, 1.1.1.1 -ErrorAction SilentlyContinue
# Only answer DNS on the lab IP, not the NAT one
dnscmd /ResetListenAddresses 192.168.56.20 | Out-Null

# --- OUs (each step skips objects that already exist, so the script is safe to re-run)
function New-LabOu($Name, $Path) {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$Name'" -SearchBase $Path -SearchScope OneLevel)) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false
    }
}
New-LabOu "Lab" $domainDn
foreach ($ou in "HR", "Finance", "IT", "ServiceAccounts", "Groups", "Computers") { New-LabOu $ou $labOu }
redircmp "OU=Computers,$labOu" | Out-Null   # newly joined machines land in Lab\Computers

# --- Groups
$groups = @{ "GG-HR" = "HR staff"; "GG-Finance" = "Finance staff"; "GG-IT" = "IT staff"; "Finance-Share-RW" = "Write access to the finance share" }
foreach ($g in $groups.Keys) {
    if (Get-ADGroup -Filter "Name -eq '$g'") { continue }
    New-ADGroup -Name $g -GroupScope Global -GroupCategory Security -Path "OU=Groups,$labOu" -Description $groups[$g]
}

# --- Users (one shared lab password so you can log in as them when simulating behaviour)
$userPw = Read-Host "Password for the lab user accounts" -AsSecureString
$users = @(
    @{ Sam = "a.smith";        Name = "Alice Smith";      Ou = "HR";              Group = "GG-HR";      Title = "HR Officer" }
    @{ Sam = "b.jones";        Name = "Ben Jones";        Ou = "HR";              Group = "GG-HR";      Title = "HR Manager" }
    @{ Sam = "c.brown";        Name = "Chloe Brown";      Ou = "Finance";         Group = "GG-Finance"; Title = "Accountant" }
    @{ Sam = "d.wilson";       Name = "Daniel Wilson";    Ou = "Finance";         Group = "GG-Finance"; Title = "Finance Manager" }
    @{ Sam = "j.doe";          Name = "John Doe";         Ou = "Finance";         Group = "GG-Finance"; Title = "Payroll Clerk" }      # the "insider"
    @{ Sam = "e.taylor";       Name = "Emma Taylor";      Ou = "IT";              Group = "GG-IT";      Title = "Sysadmin" }
    @{ Sam = "f.khan";         Name = "Farah Khan";       Ou = "IT";              Group = "GG-IT";      Title = "Helpdesk" }
    @{ Sam = "old.contractor"; Name = "Old Contractor";   Ou = "IT";              Group = "GG-IT";      Title = "Contractor (left)" } # dormant account
    @{ Sam = "svc_backup";     Name = "Backup Service";   Ou = "ServiceAccounts"; Group = $null;        Title = "Service account" }
)
foreach ($u in $users) {
    if (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'") { continue }
    New-ADUser -SamAccountName $u.Sam -UserPrincipalName "$($u.Sam)@lab.local" -Name $u.Name -DisplayName $u.Name `
        -Title $u.Title -Department $u.Ou -Path "OU=$($u.Ou),$labOu" -AccountPassword $userPw `
        -Enabled $true -PasswordNeverExpires $true
    if ($u.Group) { Add-ADGroupMember -Identity $u.Group -Members $u.Sam }
}
Add-ADGroupMember -Identity "Finance-Share-RW" -Members "d.wilson", "c.brown"
# Let lab users RDP into the domain-joined client (needed for the off-hours / lateral-movement demos)
Add-ADGroupMember -Identity "Remote Desktop Users" -Members "GG-HR", "GG-Finance", "GG-IT" -ErrorAction SilentlyContinue

# --- n8n response account: may ONLY flip userAccountControl on users inside OU=Lab.
# Members of Domain Admins etc. are protected by AdminSDHolder, so this can never disable an admin.
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_n8n'")) {
    $svcPw = Read-Host "Password for svc_n8n (goes into the n8n SSH credential)" -AsSecureString
    New-ADUser -SamAccountName "svc_n8n" -UserPrincipalName "svc_n8n@lab.local" -Name "n8n SOAR Responder" `
        -Path "OU=ServiceAccounts,$labOu" -AccountPassword $svcPw -Enabled $true -PasswordNeverExpires $true `
        -Description "n8n SOAR - can disable users in OU=Lab only"
}
dsacls $labOu /I:S /G "LAB\svc_n8n:RPWP;userAccountControl;user" | Out-Null

# --- OpenSSH server so n8n's SSH node can run Disable-ADAccount on the DC
if ((Get-WindowsCapability -Online -Name "OpenSSH.Server*").State -ne "Installed") {
    Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0" | Out-Null
}
Set-Service sshd -StartupType Automatic
Start-Service sshd
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null
if (-not (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" -Protocol TCP -LocalPort 22 -Direction Inbound -Action Allow | Out-Null
}
# Lab network only. Server 2025's built-in rule is Private-profile only, but a DC's network is "Domain".
Set-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -RemoteAddress 192.168.56.0/24 -Profile Any

Write-Host "`nDone. Summary:"
Get-ADUser -Filter * -SearchBase $labOu -Properties Title | Format-Table SamAccountName, Name, Title, Enabled -AutoSize
Write-Host "Next: 04-audit-policy.ps1, then 05-sysmon-and-agent.ps1"

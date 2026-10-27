# Run INSIDE DC01 as LAB\Administrator. Generates the insider-threat events your detections look for.
# Pick a scenario:  .\07-simulate-insider.ps1 -Scenario BruteForce
# Lab only - this creates accounts and changes group membership in lab.local.

param(
    [ValidateSet("BruteForce", "Lockout", "PrivEsc", "RogueAccount", "LogClear", "All")]
    [string]$Scenario = "BruteForce",
    [string]$Target   = "j.doe",
    # Separate user on purpose: once an account has been in Domain Admins, AdminSDHolder locks its ACL
    # and svc_n8n can no longer disable it - so don't escalate the account you use for the disable demo.
    [string]$PrivTarget = "f.khan",
    [string]$Dc       = "dc01.lab.local"
)

$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory

function Invoke-FailedLogons([string]$user, [int]$count) {
    # Each failed bind = 4625 + 4771/4776 on the DC
    for ($i = 1; $i -le $count; $i++) {
        $entry = New-Object DirectoryServices.DirectoryEntry("LDAP://$Dc", "LAB\$user", "Wrong-Password-$i")
        try { $null = $entry.NativeObject } catch { }
        Start-Sleep -Milliseconds 300
    }
    Write-Host "[$user] $count failed logons sent"
}

switch ($Scenario) {
    "BruteForce"   { Invoke-FailedLogons $Target 9 }                                     # rule: >= 8 x 4625 in 5 min
    "Lockout"      { Invoke-FailedLogons $Target 11; Write-Host "Unlock later: Unlock-ADAccount $Target" }   # 4740
    "PrivEsc"      { Add-ADGroupMember "Domain Admins" -Members $PrivTarget; Write-Host "Revert: Remove-ADGroupMember 'Domain Admins' $PrivTarget" }  # 4728
    "RogueAccount" {                                                                     # 4720 + 4728
        New-ADUser -SamAccountName "admin_tmp" -Name "admin_tmp" -Path "OU=IT,OU=Lab,$((Get-ADDomain).DistinguishedName)" `
            -AccountPassword (ConvertTo-SecureString "Tmp!$(Get-Random)aA1" -AsPlainText -Force) -Enabled $true
        Add-ADGroupMember "Domain Admins" -Members "admin_tmp"
        Write-Host "Revert: Remove-ADUser admin_tmp"
    }
    "LogClear"     { Start-Sleep 60; wevtutil cl Security; Write-Host "Security log cleared (1102)" }  # wait so Agent ships the earlier events first
    "All"          {
        foreach ($s in "BruteForce", "PrivEsc", "RogueAccount") { & $PSCommandPath -Scenario $s -Target $Target -Dc $Dc }
    }
}

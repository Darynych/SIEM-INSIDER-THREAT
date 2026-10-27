# Run INSIDE DC01 (and on the domain-joined client) as Administrator.
# Turns on the Advanced Audit subcategories the detections depend on (ROADMAP §5).
# Without this, AD is quiet: no 4720/4728/4740 etc. ever reach Elastic.

$ErrorActionPreference = "Stop"

# Make "Advanced Audit" settings win over legacy category-level policy
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord

$subcategories = @(
    "Credential Validation",                 # 4776
    "Kerberos Authentication Service",       # 4768, 4771
    "Kerberos Service Ticket Operations",    # 4769
    "Logon",                                 # 4624, 4625
    "Logoff",                                # 4634, 4647
    "Account Lockout",                       # 4740 (logged on the DC)
    "Special Logon",                         # 4672
    "User Account Management",               # 4720, 4722, 4725, 4726, 4738
    "Security Group Management",             # 4728, 4732, 4756
    "Directory Service Changes",             # 5136
    "Process Creation",                      # 4688
    "Audit Policy Change"                    # 4719
)
foreach ($s in $subcategories) {
    auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
}

# Include the full command line in 4688 process-creation events
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord

# Bigger Security log so a burst of events isn't rolled over before Elastic Agent ships it
wevtutil sl Security /ms:524288000

# Lockout policy so the "Account Lockout" (4740) detection can actually fire (domain-wide, DC only)
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
    Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot `
        -LockoutThreshold 10 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00
}

auditpol /get /category:* | Select-String "Success|Failure|No Auditing" | Select-Object -First 60

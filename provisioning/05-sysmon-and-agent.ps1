# Run INSIDE DC01 (and the client) as Administrator.
# Installs Sysmon (SwiftOnSecurity config) and enrolls Elastic Agent into your Fleet.
# Get the token from Kibana -> Fleet -> Enrollment tokens (use a policy that has the System + Windows integrations).

param(
    [Parameter(Mandatory)] [string]$EnrollmentToken,
    [string]$FleetUrl     = "https://192.168.56.10:8220",
    [string]$AgentVersion = "",            # must not be newer than your Fleet Server, e.g. 8.19.16
    [string]$CaCert       = "",            # Lab Fleet CA (/etc/fleet-certs/ca.crt on the SIEM server) - verifies Fleet's cert
    [switch]$Insecure                      # skip Fleet cert checks entirely (only if you have no CA)
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # PS 5's progress bar makes big downloads crawl (and the agent zip is ~270 MB)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$work = "C:\LabSetup"; New-Item -ItemType Directory -Force -Path $work | Out-Null

# --- Sysmon
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$work\Sysmon.zip"
Expand-Archive "$work\Sysmon.zip" -DestinationPath "$work\Sysmon" -Force
Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$work\sysmonconfig.xml"
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    & "$work\Sysmon\Sysmon64.exe" -c "$work\sysmonconfig.xml"
} else {
    & "$work\Sysmon\Sysmon64.exe" -accepteula -i "$work\sysmonconfig.xml"
}

# --- Elastic Agent
$agentArgs = @("--url=$FleetUrl", "--enrollment-token=$EnrollmentToken")
if ($CaCert)   { $agentArgs += "--certificate-authorities=$CaCert" }
if ($Insecure) { $agentArgs += "--insecure" }

$installedAgent = "C:\Program Files\Elastic\Agent\elastic-agent.exe"
if (Test-Path $installedAgent) {
    # Already installed (e.g. enrolled into another policy earlier): just move it to this policy / Fleet
    & $installedAgent enroll @agentArgs --force
} else {
    if (-not $AgentVersion) { $AgentVersion = Read-Host "Elastic stack version (Kibana -> Help -> About), e.g. 8.15.0" }
    $zip = "elastic-agent-$AgentVersion-windows-x86_64"
    Remove-Item "$work\$zip.zip" -ErrorAction SilentlyContinue   # don't reuse a half-finished download
    Invoke-WebRequest "https://artifacts.elastic.co/downloads/beats/elastic-agent/$zip.zip" -OutFile "$work\$zip.zip"
    Expand-Archive "$work\$zip.zip" -DestinationPath $work -Force
    & "$work\$zip\elastic-agent.exe" install @agentArgs --non-interactive
}

Write-Host "`nCheck Kibana -> Fleet -> Agents for $env:COMPUTERNAME, then Discover: event.code:4624 and winlog.channel:`"Microsoft-Windows-Sysmon/Operational`""

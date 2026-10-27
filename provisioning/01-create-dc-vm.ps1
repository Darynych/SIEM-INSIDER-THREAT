# Run on the Windows HOST (normal PowerShell, not inside a VM).
# Creates the DC01 VirtualBox VM and installs Windows Server 2025 unattended.
#   NIC1 = NAT (internet for updates/downloads)   NIC2 = host-only 192.168.56.0/24 (lab network, same as the SIEM server)

param(
    [string]$VmName  = "DC01",
    [string]$IsoPath = "$env:USERPROFILE\VirtualBox VMs\26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso",
    [int]$MemoryMB   = 4096,
    [int]$Cpus       = 2,
    [int]$DiskMB     = 61440,
    [int]$ImageIndex = 2,  # Server 2025 eval ISO: 1 = Standard Core, 2 = Standard (Desktop Experience)
    [string]$AdminPassword = ""   # leave empty to be prompted
)

$ErrorActionPreference = "Stop"
$vbm = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

if (-not (Test-Path $IsoPath)) { throw "ISO not found: $IsoPath" }
if ((& $vbm list vms) -match "`"$VmName`"") { throw "A VM called '$VmName' already exists." }

$plain = $AdminPassword
if (-not $plain) {
    $pw = Read-Host "Password for the local Administrator (becomes the domain Administrator)" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
}

$vmDir = Join-Path "$env:USERPROFILE\VirtualBox VMs" $VmName
$disk  = Join-Path $vmDir "$VmName.vdi"

& $vbm createvm --name $VmName --ostype Windows2022_64 --register
& $vbm modifyvm $VmName --memory $MemoryMB --cpus $Cpus --vram 128 --graphicscontroller vboxsvga `
    --nic1 nat --nic2 hostonly --hostonlyadapter2 "VirtualBox Host-Only Ethernet Adapter" `
    --clipboard-mode bidirectional --rtc-use-utc on
& $vbm createmedium disk --filename $disk --size $DiskMB --format VDI
& $vbm storagectl $VmName --name SATA --add sata --controller IntelAhci --portcount 2
& $vbm storageattach $VmName --storagectl SATA --port 0 --device 0 --type hdd --medium $disk
& $vbm storageattach $VmName --storagectl SATA --port 1 --device 0 --type dvddrive --medium emptydrive

& $vbm unattended install $VmName --iso="$IsoPath" --image-index=$ImageIndex `
    --user=Administrator --password="$plain" --hostname="dc01.lab.local" `
    --install-additions --locale=en_US --country=GB --time-zone=UTC --start-vm=gui

Write-Host "`nWindows is installing in the DC01 window (~15-20 min, reboots a few times)."
Write-Host "When you reach the desktop, copy the provisioning folder into the VM and run 02-promote-dc.ps1 as Administrator."

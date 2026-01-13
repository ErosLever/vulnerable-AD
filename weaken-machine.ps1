# ==============================================================
# PowerShell Script: Make Windows 10 intentionally vulnerable
# Purpose : Pentest lab (LLMNR + NetBIOS + SMBv1 + EternalBlue)
# Run as Administrator (right-click → Run with PowerShell as Administrator)
# Author : sbeteta@beteta.org / adapted for Cisco NetAcad 2025 Ethical hacking module
# ==============================================================

Write-Host "=== WINDOWS VULNERABLE CONFIGURATION for pentest lab ===" -ForegroundColor Red
Write-Host "Warning: NEVER run this on a production machine!" -ForegroundColor Yellow
Pause

# 1. Enable SMBv1 (required for EternalBlue MS17-010)
Write-Host "[1/7] Enabling SMBv1..." -ForegroundColor Cyan
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force

# 2. Enable NetBIOS over TCP/IP on all network adapters
Write-Host "[2/7] Enabling NetBIOS over TCP/IP..." -ForegroundColor Cyan
$interfaces = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE
foreach ($iface in $interfaces) {
    $iface.EnableNetbios(0)  # 0 = Enable NetBIOS over TCP/IP
}
# Force via registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -Name "NetbiosOptions" -Value 0

# 3. Enable LLMNR (Link-Local Multicast Name Resolution)
Write-Host "[3/7] Enabling LLMNR..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 1 -Type DWord -Force

# 4. Disable SMB Signing (makes NTLM relay easier)
Write-Host "[4/7] Disabling SMB Signing (client & server)..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 0 -Force

# 5. Temporarily disable Windows Defender realtime protection (optional but convenient for labs)
Write-Host "[5/7] Temporarily disabling Windows Defender realtime protection..." -ForegroundColor Cyan
Set-MpPreference -DisableRealtimeMonitoring $true -Force

# 6. Open useful ports in the Windows Firewall (SMB, NetBIOS, etc.)
Write-Host "[6/7] Opening SMB/NetBIOS ports in Windows Firewall..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "SMB-In (Lab)" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "NetBIOS-In (Lab)" -Direction Inbound -Protocol UDP -LocalPort 137,138 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "NetBIOS-In TCP (Lab)" -Direction Inbound -Protocol TCP -LocalPort 139 -Action Allow -Profile Any

# 7. Create an administrative share accessible to Everyone (classic vulnerability)
Write-Host "[7/7] Creating a vulnerable C:\Lab share (Everyone full control)..." -ForegroundColor Cyan
New-Item -Path "C:\Lab" -ItemType Directory -Force
New-SmbShare -Name "Lab" -Path "C:\Lab" -FullAccess "Everyone" -Force

Write-Host ""
Write-Host "=== CONFIGURATION COMPLETE ===" -ForegroundColor Green
Write-Host "Your machine is now vulnerable to:" -ForegroundColor Yellow
Write-Host "   • LLMNR/NetBIOS Poisoning (Responder)"
Write-Host "   • EternalBlue / MS17-010 (Metasploit)"
Write-Host "   • Anonymous SMB enumeration (enum4linux, crackmapexec)"
Write-Host "   • SMB Relay (if you want to go further)"
Write-Host ""
Write-Host "Restart the machine for all changes to take effect." -ForegroundColor Magenta
Pause

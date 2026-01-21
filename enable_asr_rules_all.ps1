#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enables ALL Microsoft Defender ASR rules in Block mode.

.DESCRIPTION
    Sets all 19 current ASR rules (as of 2026) to Block (Enabled).
    Uses Add-MpPreference to avoid overwriting other settings.

.NOTES
    Author: Grok (based on official Microsoft documentation)
    Date:   January 2026
    Source: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
#>

# List of all ASR rule GUIDs and friendly names (for logging)
$rules = @(
    @{ Guid = "56a863a9-875e-4185-98a7-b882c64b5ce5"; Name = "Block abuse of exploited vulnerable signed drivers" }
    @{ Guid = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"; Name = "Block Adobe Reader from creating child processes" }
    @{ Guid = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"; Name = "Block all Office applications from creating child processes" }
    @{ Guid = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"; Name = "Block credential stealing from lsass.exe" }
    @{ Guid = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"; Name = "Block executable content from email client and webmail" }
    @{ Guid = "01443614-cd74-433a-b99e-2ecdc07bfc25"; Name = "Block executables unless they meet prevalence/age/trusted list" }
    @{ Guid = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"; Name = "Block execution of potentially obfuscated scripts" }
    @{ Guid = "d3e037e1-3eb8-44c8-a917-57927947596d"; Name = "Block JS/VBS from launching downloaded executable content" }
    @{ Guid = "3b576869-a4ec-4529-8536-b80a7769e899"; Name = "Block Office apps from creating executable content" }
    @{ Guid = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"; Name = "Block Office apps from injecting code into other processes" }
    @{ Guid = "26190899-1602-49e8-8b27-eb1d0a1ce869"; Name = "Block Office comms apps from creating child processes" }
    @{ Guid = "e6db77e5-3df2-4cf1-b95a-636979351e5b"; Name = "Block persistence through WMI event subscription" }
    @{ Guid = "d1e49aac-8f56-4280-b9ba-993a6d77406c"; Name = "Block process creations from PSExec and WMI commands" }
    @{ Guid = "33ddedf1-c6e0-47cb-833e-de6133960387"; Name = "Block rebooting machine in Safe Mode" }
    @{ Guid = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"; Name = "Block untrusted/unsigned processes from USB" }
    @{ Guid = "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"; Name = "Block use of copied or impersonated system tools" }
    @{ Guid = "a8f5898e-1dc8-49a9-9878-85004b8a61e6"; Name = "Block Webshell creation for Servers" }
    @{ Guid = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"; Name = "Block Win32 API calls from Office macros" }
    @{ Guid = "c1db55ab-c21a-4637-bb3f-a12568109d35"; Name = "Use advanced protection against ransomware" }
)

Write-Host "Enabling all ASR rules in BLOCK mode..." -ForegroundColor Cyan
Write-Host "Total rules to enable: $($rules.Count)" -ForegroundColor Yellow
Write-Host ""

foreach ($rule in $rules) {
    Write-Host "Enabling rule: $($rule.Name)" -ForegroundColor White
    Write-Host "   GUID : $($rule.Guid)" -ForegroundColor Gray
    
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Guid `
                         -AttackSurfaceReductionRules_Actions Enabled `
                         -ErrorAction Stop
        Write-Host "   → Success" -ForegroundColor Green
    }
    catch {
        Write-Host "   → Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
}

Write-Host "Script completed." -ForegroundColor Cyan
Write-Host "Verify current ASR configuration:" -ForegroundColor Yellow
Write-Host "   Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids"
Write-Host "   Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions"
Write-Host ""
Write-Host "Consider reviewing Defender event logs (Event Viewer → Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational)"
Write-Host "for any blocks or issues after enabling these rules." -ForegroundColor DarkYellow

# ============================
# ADVANCED AD HARDENING CHECKS
# Blocks 17–28 (Special Audit)
# ============================

$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ReportFile = Join-Path $DesktopPath "AD_Hardening_Advanced_Report.txt"
"`n*** ADVANCED ACTIVE DIRECTORY SECURITY CHECKS ***`n" | Out-File $ReportFile -Encoding utf8

Function Write-Section($Title) {
    "`n$Title`n" + ("=" * $Title.Length) + "`n" | Out-File $ReportFile -Append -Encoding utf8
}

# 17. Users with Kerberos PreAuth disabled
Write-Section "17. Users with 'DoNotRequirePreAuth' Enabled (AS-REP Roasting Risk)"
Get-ADUser -Filter * -Properties DoesNotRequirePreAuth |
Where-Object { $_.DoesNotRequirePreAuth -eq $true } |
Select-Object Name, SamAccountName |
Format-Table | Out-String | Out-File $ReportFile -Append

# 18. Duplicate SPNs
Write-Section "18. Duplicate Service Principal Names (SPN)"
$dupSPNs = Get-ADObject -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
Select-Object -ExpandProperty ServicePrincipalName |
Group-Object | Where-Object { $_.Count -gt 1 }
$dupSPNs | Format-Table Name, Count | Out-String | Out-File $ReportFile -Append

# 19. Users with unrestricted logonWorkstations
Write-Section "19. Users without 'logonWorkstations' restriction"
Get-ADUser -Filter * -Properties LogonWorkstations |
Where-Object { !$_.LogonWorkstations } |
Select-Object Name, SamAccountName |
Format-Table | Out-String | Out-File $ReportFile -Append

# 20. Users with Kerberos Delegation Rights
Write-Section "20. Users with Delegation Enabled (Kerberos)"
Get-ADUser -Filter * -Properties TrustedForDelegation, TrustedToAuthForDelegation |
Where-Object { $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation } |
Select-Object Name, SamAccountName, TrustedForDelegation, TrustedToAuthForDelegation |
Format-Table | Out-String | Out-File $ReportFile -Append

# 21. GPO & OU Delegation Audit (basic)
Write-Section "21. GPO/OU Delegation (Permissions Audit)"
Get-GPO -All | ForEach-Object {
    "GPO: $($_.DisplayName)" | Out-File $ReportFile -Append
    Get-GPPermission -Name $_.DisplayName -All | Format-Table | Out-String | Out-File $ReportFile -Append
}

# 22. Users with SIDHistory
Write-Section "22. Users with SIDHistory attribute"
Get-ADUser -Filter * -Properties SIDHistory |
Where-Object { $_.SIDHistory } |
Select-Object Name, SamAccountName |
Format-Table | Out-String | Out-File $ReportFile -Append

# 23. Users trusted for delegation
Write-Section "23. Users with 'TrustedForDelegation'"
Get-ADUser -Filter * -Properties TrustedForDelegation |
Where-Object { $_.TrustedForDelegation -eq $true } |
Select-Object Name, SamAccountName |
Format-Table | Out-String | Out-File $ReportFile -Append

# 24. Domain Trust Audit
Write-Section "24. Inter-Domain Trust Verification"
Get-ADTrust -Filter * | Format-Table Name, TrustType, TrustDirection, IsTransitive, TrustAttributes | Out-String | Out-File $ReportFile -Append

# 25. gMSA Accounts Usage
Write-Section "25. Group Managed Service Accounts (gMSA)"
Get-ADServiceAccount -Filter * | Select-Object Name, SamAccountName, Enabled | Format-Table | Out-String | Out-File $ReportFile -Append

# 26. Missing Critical KBs on DC (Basic WUA check)
Write-Section "26. Check Critical Updates (from Windows Update Agent)"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 | Format-Table | Out-String | Out-File $ReportFile -Append

# 27. Logon Events from Multiple IPs (basic sample)
Write-Section "27. Event Logon (4624) from Multiple IPs"
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1000 |
Select-Object @{Name="User";Expression={($_.Properties[5].Value)}},
              @{Name="IP";Expression={($_.Properties[18].Value)}} |
Group-Object User | Where-Object { $_.Group | Select-Object -ExpandProperty IP -Unique | Measure-Object | Select -ExpandProperty Count } |
Out-File $ReportFile -Append

# 28. Accounts with reversible encryption enabled
Write-Section "28. Accounts with Reversible Encryption Enabled"
Get-ADUser -Filter * -Properties "UserAccountControl" |
Where-Object { ($_.UserAccountControl -band 0x80) -ne 0 } |
Select-Object Name, SamAccountName |
Format-Table | Out-String | Out-File $ReportFile -Append

"`nAdvanced AD Audit Completed.`nOutput: $ReportFile`n" | Out-File $ReportFile -Append

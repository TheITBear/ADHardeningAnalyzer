# ============================================
# POWERSHELL INTERACTIVE WRAPPER SCRIPT
# COMPLETE ACTIVE DIRECTORY HARDENING ANALYSIS
# ============================================

Clear-Host
Write-Host "*** INTERACTIVE AD HARDENING SCRIPT ***" -ForegroundColor Cyan
Write-Host "Checks Active Directory security and exports the results in multiple formats."

# Check for administrative privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "You must run this script as Administrator." -ForegroundColor Red
    Pause
    exit
}

# Ask whether to include optional modules
$includeExcel = Read-Host "Do you want to enable Excel export (ImportExcel module)? (y/n)"
$includeDocx  = Read-Host "Do you want to generate the Word (.docx) report as well? (y/n)"

# Load optional modules if selected
if ($includeExcel -eq 'y') {
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-Host "Installing ImportExcel module..."
        Install-Module -Name ImportExcel -Force -Scope CurrentUser
    }
    Import-Module ImportExcel
}

if ($includeDocx -eq 'y') {
    if (-not (Get-Module -ListAvailable -Name Word)) {
        Write-Host "Installing Word automation module..."
        Install-Module -Name Word -Force -Scope CurrentUser
    }
    Import-Module Word
}

# Confirm to continue with main AD analysis
$confirm = Read-Host "Proceed with AD analysis and report generation? (y/n)"
if ($confirm -ne 'y') {
    Write-Host "Operation canceled."
    exit
}

# Path definitions
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$MainReport = Join-Path $DesktopPath "AD_Hardening_Report.txt"
$CSVFolder = Join-Path $DesktopPath "AD_Hardening_CSVs"
$DocxPath = Join-Path $DesktopPath "AD_Hardening_Report.docx"
New-Item -ItemType Directory -Path $CSVFolder -Force | Out-Null

# Initialize report
"ACTIVE DIRECTORY HARDENING REPORT`n===============================`n" | Out-File $MainReport -Encoding utf8

function Write-Section {
    param ($Title)
    "`n$Title`n" + ("-" * $Title.Length) + "`n" | Out-File $MainReport -Append -Encoding utf8
}

# SECTION 1: Inactive users
Write-Section "1. Users with last logon older than 30 days"
$InactiveUsers = Get-ADUser -Filter * -Properties LastLogonTimestamp |
    Where-Object { ([datetime]::FromFileTime($_.LastLogonTimestamp)) -lt (Get-Date).AddDays(-30) } |
    Select-Object Name, SamAccountName, @{Name="LastLogonDate";Expression={[datetime]::FromFileTime($_.LastLogonTimestamp)}}
$InactiveUsers | Format-Table | Out-String | Out-File $MainReport -Append
$InactiveUsers | Export-Csv "$CSVFolder\InactiveUsers.csv" -NoTypeInformation

# SECTION 2: Inactive computers
Write-Section "2. Computers with last logon older than 30 days"
$InactiveComputers = Get-ADComputer -Filter * -Properties LastLogonTimestamp |
    Where-Object { ([datetime]::FromFileTime($_.LastLogonTimestamp)) -lt (Get-Date).AddDays(-30) } |
    Select-Object Name, OperatingSystem, @{Name="LastLogonDate";Expression={[datetime]::FromFileTime($_.LastLogonTimestamp)}}
$InactiveComputers | Format-Table | Out-String | Out-File $MainReport -Append
$InactiveComputers | Export-Csv "$CSVFolder\InactiveComputers.csv" -NoTypeInformation

# SECTION 3: Privileged Groups
Write-Section "3. Privileged Groups"
$PrivGroups = "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"
foreach ($group in $PrivGroups) {
    "Group: $group" | Out-File $MainReport -Append
    try {
        Get-ADGroupMember -Identity $group -Recursive | Select-Object Name, SamAccountName | Format-Table | Out-String | Out-File $MainReport -Append
    } catch {
        "Group not found or inaccessible: $group" | Out-File $MainReport -Append
    }
}

# SECTION 4: Privileged Users CSV
Write-Section "4. All Privileged Users (exported)"
$PrivilegedUsers = foreach ($g in $PrivGroups) {
    Get-ADGroupMember -Identity $g -Recursive | Select-Object Name, SamAccountName, objectClass
}
$PrivilegedUsers | Export-Csv "$CSVFolder\PrivilegedUsers.csv" -NoTypeInformation
$PrivilegedUsers | Format-Table | Out-String | Out-File $MainReport -Append

# ... (TO CONTINUE: sections 5 to 16 will be appended next)

# SECTION 5: Users with Password Never Expires
Write-Section "5. Users with 'Password Never Expires'"
$noExpireUsers = Get-ADUser -Filter * -Properties PasswordNeverExpires |
    Where-Object { $_.PasswordNeverExpires -eq $true } |
    Select-Object Name, SamAccountName
$noExpireUsers | Format-Table | Out-String | Out-File $MainReport -Append

# SECTION 6: Non-Privileged Objects with AdminCount = 1
Write-Section "6. Non-Privileged Users with AdminCount = 1"
$adminCountUsers = Get-ADUser -Filter 'adminCount -eq 1' -Properties MemberOf |
    Where-Object { ($_.MemberOf -notmatch "Domain Admins|Enterprise Admins|Schema Admins") } |
    Select-Object Name, SamAccountName
$adminCountUsers | Format-Table | Out-String | Out-File $MainReport -Append

# SECTION 7: OU Structure Report
Write-Section "7. OU Structure"
$OUList = Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
$OUList | Format-Table | Out-String | Out-File $MainReport -Append

# SECTION 8: Clients with Obsolete Operating Systems
Write-Section "8. Clients with Obsolete Operating Systems"
$legacyOS = Get-ADComputer -Filter * -Properties OperatingSystem |
    Where-Object { $_.OperatingSystem -match "Windows (XP|7|2008|Vista|8)" } |
    Select-Object Name, OperatingSystem
$legacyOS | Format-Table | Out-String | Out-File $MainReport -Append

# SECTION 9: SMBv1 Status
Write-Section "9. SMBv1 Activation Status"
$smbv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"
$smbv1 | Out-String | Out-File $MainReport -Append

# SECTION 10: NTLM Status (via Registry)
Write-Section "10. NTLM Configuration Status"
$ntlmSettings = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" |
    Select-Object LmCompatibilityLevel
$ntlmSettings | Out-String | Out-File $MainReport -Append

# SECTION 11: LDAP Signing / Channel Binding
Write-Section "11. LDAP Signing and Channel Binding"
$ldapSign = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
$channelBind = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPEnforceChannelBinding" -ErrorAction SilentlyContinue
$ldapSign, $channelBind | Format-List | Out-String | Out-File $MainReport -Append

# SECTION 12: Print Spooler Service Status
Write-Section "12. Print Spooler Service Status"
$spooler = Get-Service -Name spooler
$spooler | Format-List | Out-String | Out-File $MainReport -Append

# SECTION 13: Firewall Status and Open Ports
Write-Section "13. Windows Firewall State & Listening Ports"
(Get-NetFirewallProfile | Select-Object Name, Enabled) | Out-String | Out-File $MainReport -Append
"Open Listening Ports:" | Out-File $MainReport -Append
netstat -ano | Select-String "LISTENING" | Out-File $MainReport -Append

# SECTION 14: GPO Report Export
Write-Section "14. GPO Report (Export to HTML)"
$GPOHTML = Join-Path $DesktopPath "GPO_Report.html"
Get-GPOReport -All -ReportType Html -Path $GPOHTML
"Generated GPO HTML Report: $GPOHTML" | Out-File $MainReport -Append

# SECTION 15: LSASS Protection (RunAsPPL)
Write-Section "15. LSASS RunAsPPL Status"
$lsass = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
$lsass | Out-String | Out-File $MainReport -Append

# SECTION 16: LAPS Configuration Check
Write-Section "16. LAPS Configuration Status"
$laps = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue
$laps | Out-String | Out-File $MainReport -Append

# Final note
"`nAnalysis completed. Reports saved on Desktop.`n" | Out-File $MainReport -Append

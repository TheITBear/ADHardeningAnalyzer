<#
.SYNOPSIS
  AD-Hardening-Analyzer.ps1 - Read-only Active Directory hardening assessment.

.DESCRIPTION
  Single, non-interactive, read-only analyzer (no changes are made to AD or DCs).
  - AD data is collected ONCE (users, computers, privileged groups) and reused by all checks.
  - DC-scoped checks run on ALL domain controllers in parallel via WinRM (Invoke-Command fan-out),
    not on the machine running the script.
  - Every check produces a finding with severity (High/Medium/Low/Info/OK/Error), a CSV with
    the affected objects, and an entry in the TXT/HTML report (optional XLSX via ImportExcel).

  Checks
    Base       01 Inactive users            02 Inactive computers        03 Privileged group membership
               04 Password never expires    05 Orphaned adminCount=1     06 OU structure / accidental deletion
               07 Unsupported OS            08 SMBv1 on DCs              09 NTLM LmCompatibilityLevel on DCs
               10 LDAP signing/channel bind 11 Print Spooler on DCs      12 Firewall + listening ports on DCs
               13 GPO HTML export           14 LSASS RunAsPPL on DCs     15 LAPS coverage
    Advanced   16 AS-REP roastable          17 Duplicate SPNs            18 Privileged account protections
               19 Kerberos delegation       20 RBCD                      21 GPO edit permissions
               22 SIDHistory                23 Kerberoastable accounts   24 Trusts
               25 gMSA inventory            26 DC patch recency          27 NTLMv1 logons observed (4624)
               28 Unsigned LDAP binds (2887/2889)                        29 Reversible encryption
               30 Password policy (CIS)     31 krbtgt password age       32 PASSWD_NOTREQD
               33 MachineAccountQuota       34 AD Recycle Bin            35 Pre-Windows 2000 Compatible Access

  The file is intentionally pure ASCII (Windows PowerShell 5.1 reads BOM-less files as ANSI).

.PARAMETER OutputPath
  Output folder. Default: <Desktop>\ADHardening_<yyyyMMdd_HHmmss>

.PARAMETER Server
  Domain controller to query for AD data. Default: auto-discovered (PDC emulator).

.PARAMETER InactiveDays
  Threshold for inactive users/computers (LastLogonTimestamp replicates every 9-14 days). Default: 90.

.PARAMETER EventHours
  Look-back window for Security / Directory Service events on DCs. Default: 24.

.PARAMETER MaxEvents
  Max events read per DC per query. Default: 5000.

.PARAMETER SkipDCChecks
  Skip remote checks on domain controllers (AD-only assessment).

.PARAMETER Excel
  Also produce an XLSX workbook (requires the ImportExcel module; it is NOT auto-installed).

.PARAMETER ThrottleLimit
  Max concurrent WinRM connections. Default: 16.

.EXAMPLE
  .\AD-Hardening-Analyzer.ps1
  .\AD-Hardening-Analyzer.ps1 -InactiveDays 60 -EventHours 72 -Excel
  .\AD-Hardening-Analyzer.ps1 -SkipDCChecks -OutputPath D:\Audit
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [string]$Server = "",
    [ValidateRange(1, 3650)]    [int]$InactiveDays = 90,
    [ValidateRange(1, 720)]     [int]$EventHours = 24,
    [ValidateRange(1, 1000000)] [int]$MaxEvents = 5000,
    [switch]$SkipDCChecks,
    [switch]$Excel,
    [ValidateRange(1, 256)]     [int]$ThrottleLimit = 16,
    [ValidateRange(1, 600)]     [int]$ConnectTimeoutSec = 15,
    [ValidateRange(5, 3600)]    [int]$OperationTimeoutSec = 300
)

# Version 1: catches uninitialized variables without breaking on optional AD attributes
Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"

# ============================== Utilities ==============================
if (-not $OutputPath) {
    $OutputPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "ADHardening_$Stamp"
}
$CsvDir = Join-Path $OutputPath "csv"
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$LogFile = Join-Path $OutputPath "run.log"

function Write-Log {
    param([string]$Message, [ValidateSet("INFO","WARN","ERROR")] [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date).ToString("HH:mm:ss"), $Level, $Message
    $color = switch ($Level) { "WARN" { "Yellow" } "ERROR" { "Red" } default { "Gray" } }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Get-Prop($Object, [string]$Name) {
    # Safe read of optional attributes (AD objects omit empty attributes)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

function Join-Values($v) { if ($null -eq $v) { "" } else { (@($v) | ForEach-Object { [string]$_ }) -join "; " } }

function ConvertTo-HtmlSafe($s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }

$SevOrder = @{ "Error" = 5; "High" = 4; "Medium" = 3; "Low" = 2; "Info" = 1; "OK" = 0 }
$Results = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    <#
      Registers a finding. If -SeverityIfFound is used, severity is that value when -Data has rows, OK otherwise.
    #>
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Title,
        [ValidateSet("High","Medium","Low","Info","OK","Error")] [string]$Severity,
        [ValidateSet("High","Medium","Low","Info")] [string]$SeverityIfFound,
        [string]$Summary = "",
        [object[]]$Data = @(),
        [string]$Recommendation = ""
    )
    $rows = @($Data | Where-Object { $null -ne $_ })
    if (-not $Severity) { $Severity = if ($rows.Count) { $SeverityIfFound } else { "OK" } }
    $csv = ""
    if ($rows.Count) {
        $slug = ($Title -replace '[^A-Za-z0-9]+', '_').Trim('_')
        $csv = Join-Path $CsvDir ("{0}_{1}.csv" -f $Id, $slug)
        $rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    }
    if (-not $Summary) { $Summary = "{0} item(s)" -f $rows.Count }
    $Results.Add([pscustomobject]@{
        Id = $Id; Title = $Title; Severity = $Severity; Count = $rows.Count
        Summary = $Summary; Recommendation = $Recommendation; Csv = $csv; Data = $rows
    })
    $lvl = if ($Severity -in "High","Error") { "WARN" } else { "INFO" }
    Write-Log ("[{0}] {1}: {2} - {3}" -f $Id, $Title, $Severity, $Summary) $lvl
}

function Invoke-Check {
    # Isolates each check: one failure never stops the assessment
    param([string]$Id, [string]$Title, [scriptblock]$Body)
    try { & $Body }
    catch { Add-Check -Id $Id -Title $Title -Severity Error -Summary ("Check failed: {0}" -f $_.Exception.Message) }
}

# ============================== Preflight ==============================
Write-Log "Output: $OutputPath"
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "ActiveDirectory module not found. Install RSAT: Install-WindowsFeature RSAT-AD-PowerShell,GPMC (Server) or Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 (Client)."
}
Import-Module ActiveDirectory -ErrorAction Stop
$HasGP = [bool](Get-Module -ListAvailable -Name GroupPolicy)
if ($HasGP) { Import-Module GroupPolicy -ErrorAction Stop } else { Write-Log "GroupPolicy module not found: GPO checks will be skipped" "WARN" }

if (-not $Server) { $Server = (Get-ADDomain).PDCEmulator }
$AD = @{ Server = $Server }
$Domain    = Get-ADDomain @AD
$Forest    = Get-ADForest @AD
$DomSid    = $Domain.DomainSID.Value
$RootSid   = if ($Forest.RootDomain -eq $Domain.DNSRoot) { $DomSid } else { (Get-ADDomain -Server $Forest.RootDomain).DomainSID.Value }
$IsRoot    = ($Forest.RootDomain -eq $Domain.DNSRoot)
$Now       = Get-Date
$Cutoff    = $Now.AddDays(-$InactiveDays)
Write-Log ("Domain: {0} (forest {1}) - querying {2}" -f $Domain.DNSRoot, $Forest.Name, $Server)

# ============================== Single-pass AD collection ==============================
$schemaNC  = (Get-ADRootDSE @AD).schemaNamingContext
$HasLegacyLaps = [bool](Get-ADObject @AD -SearchBase $schemaNC -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)')
$HasWinLaps    = [bool](Get-ADObject @AD -SearchBase $schemaNC -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)')

Write-Log "Collecting users..."
$userProps = @('Enabled','LastLogonDate','whenCreated','PasswordLastSet','PasswordNeverExpires','PasswordNotRequired',
               'adminCount','DoesNotRequirePreAuth','TrustedForDelegation','TrustedToAuthForDelegation',
               'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity','AllowReversiblePasswordEncryption',
               'AccountNotDelegated','LogonWorkstations','servicePrincipalName','Description')
$Users = @(Get-ADUser @AD -Filter * -Properties $userProps)

Write-Log "Collecting computers..."
$compProps = @('Enabled','LastLogonDate','whenCreated','OperatingSystem','OperatingSystemVersion','DNSHostName','PrimaryGroupID',
               'TrustedForDelegation','TrustedToAuthForDelegation','msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity')
if ($HasLegacyLaps) { $compProps += 'ms-Mcs-AdmPwdExpirationTime' }
if ($HasWinLaps)    { $compProps += 'msLAPS-PasswordExpirationTime' }
$Computers = @(Get-ADComputer @AD -Filter * -Properties $compProps)
Write-Log ("Users: {0} - Computers: {1}" -f $Users.Count, $Computers.Count)

function Test-IsDC($c) { (Get-Prop $c 'PrimaryGroupID') -in 516, 521 }

# Privileged groups resolved by SID (language-independent)
$PrivDefs = @(
    @{ Name = "Administrators";              Sid = "S-1-5-32-544";  Root = $false }
    @{ Name = "Domain Admins";               Sid = "$DomSid-512";   Root = $false }
    @{ Name = "Enterprise Admins";           Sid = "$RootSid-519";  Root = $true  }
    @{ Name = "Schema Admins";               Sid = "$RootSid-518";  Root = $true  }
    @{ Name = "Account Operators";           Sid = "S-1-5-32-548";  Root = $false }
    @{ Name = "Server Operators";            Sid = "S-1-5-32-549";  Root = $false }
    @{ Name = "Print Operators";             Sid = "S-1-5-32-550";  Root = $false }
    @{ Name = "Backup Operators";            Sid = "S-1-5-32-551";  Root = $false }
    @{ Name = "Group Policy Creator Owners"; Sid = "$DomSid-520";   Root = $false }
    @{ Name = "Key Admins";                  Sid = "$DomSid-526";   Root = $false }
    @{ Name = "Enterprise Key Admins";       Sid = "$RootSid-527";  Root = $true  }
)

function Get-NestedMember {
    param([string]$GroupSid, [bool]$Root)
    $srv = if ($Root -and -not $IsRoot) { $Forest.RootDomain } else { $Server }
    $g = Get-ADGroup -Server $srv -Identity $GroupSid -ErrorAction Stop
    if ($Root -and -not $IsRoot) {
        @(Get-ADGroupMember -Server $srv -Identity $g -Recursive | ForEach-Object {
            [pscustomobject]@{ DistinguishedName = $_.distinguishedName; SamAccountName = $_.SamAccountName; ObjectClass = $_.objectClass } })
    } else {
        # LDAP_MATCHING_RULE_IN_CHAIN: one query, handles deep nesting and foreign principals without errors
        @(Get-ADObject -Server $srv -LDAPFilter "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$($g.DistinguishedName)))" -Properties samAccountName |
            ForEach-Object { [pscustomobject]@{ DistinguishedName = $_.DistinguishedName; SamAccountName = $_.samAccountName; ObjectClass = $_.ObjectClass } })
    }
}

Write-Log "Resolving privileged groups..."
$PrivMembers = [System.Collections.Generic.List[object]]::new()
$PrivByDN = @{}
foreach ($def in $PrivDefs) {
    try {
        foreach ($m in (Get-NestedMember -GroupSid $def.Sid -Root $def.Root)) {
            $PrivMembers.Add([pscustomobject]@{ Group = $def.Name; SamAccountName = $m.SamAccountName; ObjectClass = $m.ObjectClass; DistinguishedName = $m.DistinguishedName })
            if (-not $PrivByDN.ContainsKey($m.DistinguishedName)) { $PrivByDN[$m.DistinguishedName] = [System.Collections.Generic.List[string]]::new() }
            $PrivByDN[$m.DistinguishedName].Add($def.Name)
        }
    } catch { Write-Log ("Unable to resolve group {0}: {1}" -f $def.Name, $_.Exception.Message) "WARN" }
}
$ProtectedUsersSet = @{}
try {
    # Protected Users (RID 525) exists only with a 2012 R2+ PDC emulator
    $ProtectedUsersDN = (Get-ADGroup @AD -Identity "$DomSid-525").DistinguishedName
    Get-ADObject @AD -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$ProtectedUsersDN)" | ForEach-Object { $ProtectedUsersSet[$_.DistinguishedName] = $true }
} catch { Write-Log "Protected Users group not found (PDC older than 2012 R2?)" "WARN" }

$PrivUsers = @($Users | Where-Object { $PrivByDN.ContainsKey($_.DistinguishedName) })
function Get-PrivGroups($dn) { if ($PrivByDN.ContainsKey($dn)) { ($PrivByDN[$dn] | Sort-Object -Unique) -join ", " } else { "" } }

# ============================== DC fan-out ==============================
$DCs = @(Get-ADDomainController @AD -Filter * | Sort-Object HostName)
$DcResults = @()
if (-not $SkipDCChecks -and $DCs.Count) {
    $DcProbe = {
        param([int]$Hours, [int]$Max)
        $ms = [int64]$Hours * 3600000
        $o = [ordered]@{}
        $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
        $o.OSBuild = if ($os) { "{0}.{1}" -f $os.CurrentBuild, $os.UBR } else { $null }

        try { $s = Get-SmbServerConfiguration -ErrorAction Stop; $o.SMB1 = [bool]$s.EnableSMB1Protocol; $o.SMBSigningRequired = [bool]$s.RequireSecuritySignature }
        catch { $o.SMB1 = $null; $o.SMBSigningRequired = $null }

        $lsa  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
        $ntds = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
        $diag = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ErrorAction SilentlyContinue
        $o.LmCompatibilityLevel      = $lsa.LmCompatibilityLevel
        $o.RunAsPPL                  = $lsa.RunAsPPL
        $o.LDAPServerIntegrity       = $ntds.LDAPServerIntegrity
        $o.LdapEnforceChannelBinding = $ntds.LdapEnforceChannelBinding
        $o.LdapDiagLevel             = if ($diag) { $diag.'16 LDAP Interface Events' } else { $null }

        $sp = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        $o.Spooler = if ($sp) { "{0}/{1}" -f $sp.Status, $sp.StartType } else { "NotInstalled" }

        $o.FirewallDisabled = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name })

        $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
        $o.Listening = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Group-Object LocalPort | ForEach-Object {
                $pidv = ($_.Group | Select-Object -First 1).OwningProcess
                [pscustomobject]@{ Port = [int]$_.Name; Process = $procs[[int]$pidv] }
            } | Sort-Object Port)

        $hf = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $o.LastHotfix   = if ($hf) { [string]$hf.HotFixID } else { $null }
        $o.LastHotfixOn = if ($hf) { [datetime]$hf.InstalledOn } else { $null }

        # NTLMv1 successful logons (4624, LmPackageName = NTLM V1): server-side XPath filter, capped
        $o.NTLMv1 = @(); $o.NTLMv1Error = $null
        $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LmPackageName']='NTLM V1']]"
        try {
            $o.NTLMv1 = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents $Max -ErrorAction Stop | ForEach-Object {
                $x = [xml]$_.ToXml(); $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
                "{0}\{1}|{2}|{3}" -f $d.TargetDomainName, $d.TargetUserName, $d.WorkstationName, $d.IpAddress
            } | Group-Object | Sort-Object Count -Descending | Select-Object -First 100 | ForEach-Object {
                $p = $_.Name.Split('|'); [pscustomobject]@{ Account = $p[0]; Workstation = $p[1]; IP = $p[2]; Count = $_.Count }
            })
        } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $o.NTLMv1Error = $_.Exception.Message } }

        # Unsigned LDAP binds: 2887 = daily summary (always logged), 2889 = per-client (needs diag level 2)
        $o.Ldap2887 = $null; $o.Ldap2889 = @()
        try {
            $e = Get-WinEvent -LogName 'Directory Service' -FilterXPath "*[System[(EventID=2887) and TimeCreated[timediff(@SystemTime) <= 86400000]]]" -MaxEvents 1 -ErrorAction Stop
            $o.Ldap2887 = "{0} simple binds w/o TLS, {1} SASL binds w/o signing (last 24h)" -f $e.Properties[0].Value, $e.Properties[1].Value
        } catch { }
        try {
            $o.Ldap2889 = @(Get-WinEvent -LogName 'Directory Service' -FilterXPath "*[System[(EventID=2889) and TimeCreated[timediff(@SystemTime) <= $ms]]]" -MaxEvents $Max -ErrorAction Stop |
                ForEach-Object { "{0}|{1}" -f ([string]$_.Properties[0].Value -replace ':\d+$', ''), $_.Properties[1].Value } |
                Group-Object | Sort-Object Count -Descending | Select-Object -First 100 | ForEach-Object {
                    $p = $_.Name.Split('|'); [pscustomobject]@{ ClientIP = $p[0]; Identity = $p[1]; Count = $_.Count } })
        } catch { }
        [pscustomobject]$o
    }

    Write-Log ("Running remote checks on {0} DC(s) in parallel..." -f $DCs.Count)
    $so = New-PSSessionOption -OpenTimeout ($ConnectTimeoutSec * 1000) -OperationTimeout ($OperationTimeoutSec * 1000) -CancelTimeout 5000
    $names = @($DCs | ForEach-Object { [string]$_.HostName })
    $errs = $null
    $raw = @(Invoke-Command -ComputerName $names -ScriptBlock $DcProbe -ArgumentList $EventHours, $MaxEvents `
        -SessionOption $so -ThrottleLimit $ThrottleLimit -ErrorAction SilentlyContinue -ErrorVariable errs)
    $byHost = @{}; foreach ($r in $raw) { $byHost[[string]$r.PSComputerName] = $r }
    $DcResults = @(foreach ($n in $names) {
        if ($byHost.ContainsKey($n)) { [pscustomobject]@{ DC = $n; Reachable = $true; Data = $byHost[$n]; Error = "" } }
        else {
            $e = @($errs) | Where-Object { [string]$_.TargetObject -eq $n -or $_.ToString() -match [regex]::Escape($n) } | Select-Object -First 1
            [pscustomobject]@{ DC = $n; Reachable = $false; Data = $null; Error = $(if ($e) { ($e.ToString() -split "`n")[0] } else { "No response" }) }
        }
    })
    Write-Log ("DC checks completed in {0:N1}s" -f $sw.Elapsed.TotalSeconds)
}
$DcOk = @($DcResults | Where-Object Reachable)

function Add-DcCheck {
    # Builds one row per reachable DC; severity applies when at least one DC is non-compliant
    param([string]$Id, [string]$Title, [string]$SeverityIfFound, [scriptblock]$Row, [string]$Recommendation)
    if ($SkipDCChecks) { Add-Check -Id $Id -Title $Title -Severity Info -Summary "Skipped (-SkipDCChecks)"; return }
    $rows = @($DcOk | ForEach-Object { $dc = $_; & $Row $dc.DC $dc.Data })
    $bad  = @($rows | Where-Object { -not $_.Compliant })
    $sev  = if ($bad.Count) { $SeverityIfFound } else { "OK" }
    Add-Check -Id $Id -Title $Title -Severity $sev -Data $rows -Recommendation $Recommendation `
        -Summary ("{0}/{1} DC non-compliant" -f $bad.Count, $rows.Count)
}

# ============================== BASE CHECKS ==============================
Invoke-Check "00" "DC reachability (WinRM)" {
    if ($SkipDCChecks) { return }
    $bad = @($DcResults | Where-Object { -not $_.Reachable } | Select-Object DC, Error)
    Add-Check -Id "00" -Title "DC reachability (WinRM)" -SeverityIfFound High -Data $bad `
        -Summary ("{0}/{1} DC unreachable" -f $bad.Count, $DcResults.Count) -Recommendation "Verify WinRM, firewall and permissions; unreachable DCs were NOT assessed"
}

Invoke-Check "01" "Inactive users" {
    $rows = @($Users | Where-Object { $_.Enabled -and (($_.LastLogonDate -and $_.LastLogonDate -lt $Cutoff) -or (-not $_.LastLogonDate -and $_.whenCreated -lt $Cutoff)) } |
        Select-Object SamAccountName, Name, LastLogonDate, PasswordLastSet, whenCreated, @{ n = 'Privileged'; e = { Get-PrivGroups $_.DistinguishedName } } |
        Sort-Object LastLogonDate)
    Add-Check -Id "01" -Title "Inactive users" -SeverityIfFound Medium -Data $rows `
        -Summary ("{0} enabled users without logon in {1} days (or never)" -f $rows.Count, $InactiveDays) `
        -Recommendation "Disable, move to a quarantine OU, then delete after retention period"
}

Invoke-Check "02" "Inactive computers" {
    $rows = @($Computers | Where-Object { $_.Enabled -and (($_.LastLogonDate -and $_.LastLogonDate -lt $Cutoff) -or (-not $_.LastLogonDate -and $_.whenCreated -lt $Cutoff)) } |
        Select-Object Name, OperatingSystem, LastLogonDate, whenCreated | Sort-Object LastLogonDate)
    Add-Check -Id "02" -Title "Inactive computers" -SeverityIfFound Medium -Data $rows `
        -Summary ("{0} enabled computers without logon in {1} days (or never)" -f $rows.Count, $InactiveDays) `
        -Recommendation "Disable stale computer accounts (they keep valid credentials and LAPS/ACL exposure)"
}

Invoke-Check "03" "Privileged group membership" {
    $summary = ($PrivMembers | Group-Object Group | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) -join ", "
    Add-Check -Id "03" -Title "Privileged group membership" -Severity Info -Data $PrivMembers.ToArray() -Summary $summary `
        -Recommendation "Keep Tier 0 groups minimal; Schema Admins should be empty except during schema changes; Operators groups empty"
}

Invoke-Check "04" "Password never expires" {
    $rows = @($Users | Where-Object { $_.Enabled -and $_.PasswordNeverExpires } |
        Select-Object SamAccountName, Name, PasswordLastSet, @{ n = 'Privileged'; e = { Get-PrivGroups $_.DistinguishedName } }, @{ n = 'HasSPN'; e = { [bool]$_.servicePrincipalName } })
    $sev = if (@($rows | Where-Object Privileged).Count) { "High" } elseif ($rows.Count) { "Medium" } else { "OK" }
    Add-Check -Id "04" -Title "Password never expires" -Severity $sev -Data $rows `
        -Summary ("{0} enabled users ({1} privileged)" -f $rows.Count, @($rows | Where-Object Privileged).Count) `
        -Recommendation "Migrate service accounts to gMSA; remove the flag from human/privileged accounts"
}

Invoke-Check "05" "Orphaned adminCount=1" {
    # adminCount stays 1 after removal from protected groups: ACL inheritance remains disabled (SDProp leftovers)
    $rows = @($Users | Where-Object { $_.adminCount -eq 1 -and -not $PrivByDN.ContainsKey($_.DistinguishedName) -and $_.SID.Value -notmatch '-(500|502)$' } |
        Select-Object SamAccountName, Name, Enabled)
    Add-Check -Id "05" -Title "Orphaned adminCount=1" -SeverityIfFound Low -Data $rows `
        -Recommendation "Clear adminCount and re-enable ACL inheritance on objects no longer in protected groups"
}

Invoke-Check "06" "OU structure" {
    $ous = @(Get-ADOrganizationalUnit @AD -Filter * -Properties ProtectedFromAccidentalDeletion | Select-Object Name, DistinguishedName, ProtectedFromAccidentalDeletion)
    $unprot = @($ous | Where-Object { -not $_.ProtectedFromAccidentalDeletion })
    Add-Check -Id "06" -Title "OU structure" -Severity $(if ($unprot.Count) { "Low" } else { "Info" }) -Data $ous `
        -Summary ("{0} OUs, {1} not protected from accidental deletion" -f $ous.Count, $unprot.Count) `
        -Recommendation "Enable ProtectedFromAccidentalDeletion on all OUs"
}

Invoke-Check "07" "Unsupported operating systems" {
    $legacy = 'Windows (XP|Vista|7|8)\b|Windows (2000|2003|NT)|Windows Server (2000|2003|2008|2012)'
    $rows = @($Computers | Where-Object { $_.Enabled -and $_.OperatingSystem } | ForEach-Object {
        $os = [string]$_.OperatingSystem
        $st = if ($os -match $legacy) { "Unsupported" } elseif ($os -match 'Windows 10' -and $os -notmatch 'LTS[BC]') { "EOL (ESU only)" } else { $null }
        if ($st) { [pscustomobject]@{ Name = $_.Name; OperatingSystem = $os; Version = $_.OperatingSystemVersion; Status = $st; LastLogonDate = $_.LastLogonDate } }
    } | Sort-Object Status, OperatingSystem)
    $sev = if (@($rows | Where-Object Status -eq "Unsupported").Count) { "High" } elseif ($rows.Count) { "Medium" } else { "OK" }
    Add-Check -Id "07" -Title "Unsupported operating systems" -Severity $sev -Data $rows `
        -Summary (($rows | Group-Object Status | ForEach-Object { "{0}: {1}" -f $_.Name, $_.Count }) -join ", ") `
        -Recommendation "Upgrade/decommission; if not possible isolate (VLAN/firewall) and track as accepted risk"
}

Invoke-Check "08" "SMBv1 / SMB signing on DCs" {
    Add-DcCheck -Id "08" -Title "SMBv1 / SMB signing on DCs" -SeverityIfFound High -Recommendation "Disable SMB1 (audit with AuditSmb1Access first); require SMB signing" -Row {
        param($dc, $d)
        [pscustomobject]@{ DC = $dc; SMB1Enabled = $d.SMB1; SigningRequired = $d.SMBSigningRequired; Compliant = ($d.SMB1 -eq $false -and $d.SMBSigningRequired -eq $true) }
    }
}

Invoke-Check "09" "NTLM LmCompatibilityLevel on DCs" {
    Add-DcCheck -Id "09" -Title "NTLM LmCompatibilityLevel on DCs" -SeverityIfFound High -Recommendation "Audit NTLMv1 (check 27), then set 'Send NTLMv2 response only. Refuse LM & NTLM' (5) via GPO" -Row {
        param($dc, $d)
        $v = $d.LmCompatibilityLevel
        [pscustomobject]@{ DC = $dc; LmCompatibilityLevel = $(if ($null -eq $v) { "not set (default 3)" } else { $v }); Compliant = ($null -ne $v -and [int]$v -ge 5) }
    }
}

Invoke-Check "10" "LDAP signing / channel binding on DCs" {
    Add-DcCheck -Id "10" -Title "LDAP signing / channel binding on DCs" -SeverityIfFound High -Recommendation "Audit 2887/2889 (check 28), then LDAPServerIntegrity=2 and LdapEnforceChannelBinding=2 via GPO" -Row {
        param($dc, $d)
        [pscustomobject]@{ DC = $dc; LDAPServerIntegrity = $d.LDAPServerIntegrity; LdapEnforceChannelBinding = $d.LdapEnforceChannelBinding
            Compliant = ($null -ne $d.LDAPServerIntegrity -and [int]$d.LDAPServerIntegrity -ge 2 -and $null -ne $d.LdapEnforceChannelBinding -and [int]$d.LdapEnforceChannelBinding -ge 2) }
    }
}

Invoke-Check "11" "Print Spooler on DCs" {
    Add-DcCheck -Id "11" -Title "Print Spooler on DCs" -SeverityIfFound High -Recommendation "Stop and disable Spooler on DCs (PrintNightmare / printer bug coercion)" -Row {
        param($dc, $d)
        [pscustomobject]@{ DC = $dc; Spooler = $d.Spooler; Compliant = ($d.Spooler -like "Stopped/Disabled" -or $d.Spooler -eq "NotInstalled") }
    }
}

Invoke-Check "12" "Firewall profiles on DCs" {
    Add-DcCheck -Id "12" -Title "Firewall profiles on DCs" -SeverityIfFound High -Recommendation "Enable all Windows Firewall profiles; default inbound block with explicit rules" -Row {
        param($dc, $d)
        [pscustomobject]@{ DC = $dc; DisabledProfiles = (Join-Values $d.FirewallDisabled); ListeningPorts = @($d.Listening).Count; Compliant = (@($d.FirewallDisabled).Count -eq 0) }
    }
    if (-not $SkipDCChecks) {
        $ports = @($DcOk | ForEach-Object { $dc = $_.DC; @($_.Data.Listening) | ForEach-Object { [pscustomobject]@{ DC = $dc; Port = $_.Port; Process = $_.Process } } })
        Add-Check -Id "12b" -Title "Listening TCP ports on DCs" -Severity Info -Data $ports -Recommendation "Review non-standard listeners on Tier 0 hosts"
    }
}

Invoke-Check "13" "GPO HTML export" {
    if (-not $HasGP) { Add-Check -Id "13" -Title "GPO HTML export" -Severity Info -Summary "Skipped (GroupPolicy module missing)"; return }
    $gpoHtml = Join-Path $OutputPath "GPO_Report.html"
    Get-GPOReport -All -ReportType Html -Path $gpoHtml -Server $Server
    Add-Check -Id "13" -Title "GPO HTML export" -Severity Info -Summary "Exported to $gpoHtml"
}

Invoke-Check "14" "LSASS RunAsPPL on DCs" {
    Add-DcCheck -Id "14" -Title "LSASS RunAsPPL on DCs" -SeverityIfFound Medium -Recommendation "Enable LSA protection (RunAsPPL=1, or 2 on 2022/W11 22H2+) after testing LSA plug-ins/drivers" -Row {
        param($dc, $d)
        [pscustomobject]@{ DC = $dc; RunAsPPL = $d.RunAsPPL; Compliant = ($null -ne $d.RunAsPPL -and [int]$d.RunAsPPL -ge 1) }
    }
}

Invoke-Check "15" "LAPS coverage" {
    if (-not $HasLegacyLaps -and -not $HasWinLaps) {
        Add-Check -Id "15" -Title "LAPS coverage" -Severity High -Summary "LAPS schema not extended (neither legacy nor Windows LAPS)" `
            -Recommendation "Deploy Windows LAPS: Update-LapsADSchema, Set-LapsADComputerSelfPermission, LAPS GPO"
        return
    }
    $scope = @($Computers | Where-Object { $_.Enabled -and -not (Test-IsDC $_) })
    $rows = @($scope | Where-Object { -not (Get-Prop $_ 'ms-Mcs-AdmPwdExpirationTime') -and -not (Get-Prop $_ 'msLAPS-PasswordExpirationTime') } |
        Select-Object Name, OperatingSystem, LastLogonDate)
    $pct = if ($scope.Count) { [math]::Round(100 * ($scope.Count - $rows.Count) / $scope.Count, 1) } else { 100 }
    $sev = if ($pct -lt 90) { "High" } elseif ($rows.Count) { "Medium" } else { "OK" }
    Add-Check -Id "15" -Title "LAPS coverage" -Severity $sev -Data $rows `
        -Summary ("Coverage {0}% ({1} of {2} enabled non-DC computers unmanaged; schema legacy={3}, Windows LAPS={4})" -f $pct, $rows.Count, $scope.Count, $HasLegacyLaps, $HasWinLaps) `
        -Recommendation "Extend LAPS policy to all OUs; prefer Windows LAPS with encryption"
}

# ============================== ADVANCED CHECKS ==============================
Invoke-Check "16" "AS-REP roastable accounts" {
    $rows = @($Users | Where-Object { $_.Enabled -and $_.DoesNotRequirePreAuth } |
        Select-Object SamAccountName, Name, PasswordLastSet, @{ n = 'Privileged'; e = { Get-PrivGroups $_.DistinguishedName } })
    Add-Check -Id "16" -Title "AS-REP roastable accounts" -SeverityIfFound High -Data $rows -Recommendation "Remove 'Do not require Kerberos preauthentication'"
}

Invoke-Check "17" "Duplicate SPNs" {
    $map = @{}
    Get-ADObject @AD -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName, samAccountName | ForEach-Object {
        $holder = $_.samAccountName
        foreach ($spn in $_.servicePrincipalName) {
            $k = $spn.ToLowerInvariant()
            if (-not $map.ContainsKey($k)) { $map[$k] = [System.Collections.Generic.List[string]]::new() }
            if (-not $map[$k].Contains($holder)) { $map[$k].Add($holder) }
        }
    }
    $rows = @($map.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 } | ForEach-Object { [pscustomobject]@{ SPN = $_.Key; Holders = ($_.Value -join "; ") } } | Sort-Object SPN)
    Add-Check -Id "17" -Title "Duplicate SPNs" -SeverityIfFound Medium -Data $rows -Recommendation "Remove duplicates (setspn -X): they break Kerberos and force NTLM fallback"
}

Invoke-Check "18" "Privileged account protections" {
    $rows = @($PrivUsers | Where-Object Enabled | ForEach-Object {
        $issues = @()
        if (-not $_.AccountNotDelegated -and -not $ProtectedUsersSet.ContainsKey($_.DistinguishedName)) { $issues += "delegable (not sensitive / not Protected Users)" }
        if ($_.PasswordNeverExpires) { $issues += "password never expires" }
        if ($_.PasswordLastSet -and $_.PasswordLastSet -lt $Now.AddDays(-365)) { $issues += "password older than 1 year" }
        if ($_.servicePrincipalName) { $issues += "has SPN (kerberoastable)" }
        if (-not $_.LogonWorkstations) { $issues += "no logonWorkstations restriction (PAW)" }
        if ($issues) {
            [pscustomobject]@{ SamAccountName = $_.SamAccountName; Groups = (Get-PrivGroups $_.DistinguishedName); PasswordLastSet = $_.PasswordLastSet
                ProtectedUsers = $ProtectedUsersSet.ContainsKey($_.DistinguishedName); Issues = ($issues -join "; ") }
        }
    })
    Add-Check -Id "18" -Title "Privileged account protections" -SeverityIfFound Medium -Data $rows `
        -Recommendation "Protected Users + 'Account is sensitive and cannot be delegated', PAW-only logon, regular password rotation, no SPN"
}

Invoke-Check "19" "Kerberos delegation" {
    $objs = @($Users | Where-Object Enabled) + @($Computers | Where-Object { $_.Enabled -and -not (Test-IsDC $_) })
    $rows = @($objs | ForEach-Object {
        $to = Join-Values (Get-Prop $_ 'msDS-AllowedToDelegateTo')
        $type = if ($_.TrustedForDelegation) { "Unconstrained" } elseif ($_.TrustedToAuthForDelegation) { "Constrained + protocol transition" } elseif ($to) { "Constrained (Kerberos only)" } else { $null }
        if ($type) { [pscustomobject]@{ SamAccountName = $_.SamAccountName; ObjectClass = $_.ObjectClass; Type = $type; AllowedToDelegateTo = $to } }
    } | Sort-Object Type)
    $sev = if (@($rows | Where-Object Type -eq "Unconstrained").Count) { "High" } elseif (@($rows | Where-Object Type -like "*protocol*").Count) { "Medium" } elseif ($rows.Count) { "Low" } else { "OK" }
    Add-Check -Id "19" -Title "Kerberos delegation" -Severity $sev -Data $rows `
        -Summary (($rows | Group-Object Type | ForEach-Object { "{0}: {1}" -f $_.Name, $_.Count }) -join ", ") `
        -Recommendation "Remove unconstrained delegation from non-DC objects; prefer constrained/RBCD without protocol transition"
}

Invoke-Check "20" "Resource-based constrained delegation" {
    $rows = @(@($Users) + @($Computers) | Where-Object { Get-Prop $_ 'msDS-AllowedToActOnBehalfOfOtherIdentity' } | ForEach-Object {
        $sd = Get-Prop $_ 'msDS-AllowedToActOnBehalfOfOtherIdentity'
        $who = try { ($sd.Access | ForEach-Object { [string]$_.IdentityReference }) -join "; " } catch { "" }
        [pscustomobject]@{ Target = $_.SamAccountName; ObjectClass = $_.ObjectClass; AllowedPrincipals = $who }
    })
    Add-Check -Id "20" -Title "Resource-based constrained delegation" -SeverityIfFound Medium -Data $rows -Recommendation "Validate each RBCD entry; unexpected entries are a common privilege escalation path"
}

Invoke-Check "21" "GPO edit permissions" {
    if (-not $HasGP) { Add-Check -Id "21" -Title "GPO edit permissions" -Severity Info -Summary "Skipped (GroupPolicy module missing)"; return }
    $okSids = @("S-1-5-18", "S-1-5-9", "$DomSid-512", "$RootSid-519")
    $rows = @(Get-GPO -All -Server $Server | ForEach-Object {
        $g = $_
        Get-GPPermission -Guid $g.Id -All -Server $Server | Where-Object {
            $_.Permission -in 'GpoEdit', 'GpoEditDeleteModifySecurity', 'GpoCustom' -and $_.Trustee.Sid -and $okSids -notcontains $_.Trustee.Sid.Value
        } | ForEach-Object { [pscustomobject]@{ GPO = $g.DisplayName; Trustee = "{0}\{1}" -f $_.Trustee.Domain, $_.Trustee.Name; Permission = [string]$_.Permission } }
    })
    Add-Check -Id "21" -Title "GPO edit permissions" -SeverityIfFound Medium -Data $rows `
        -Recommendation "Only Tier 0 admins should edit GPOs linked to Tier 0 / domain root; review delegated editors"
}

Invoke-Check "22" "SIDHistory" {
    $rows = @(Get-ADObject @AD -LDAPFilter '(sIDHistory=*)' -Properties sIDHistory, samAccountName | ForEach-Object {
        $h = @($_.sIDHistory | ForEach-Object { [string]$_ })
        [pscustomobject]@{ SamAccountName = $_.samAccountName; ObjectClass = $_.ObjectClass; SIDHistory = ($h -join "; "); SameDomainSid = [bool]($h | Where-Object { $_ -like "$DomSid-*" }) }
    })
    $sev = if (@($rows | Where-Object SameDomainSid).Count) { "High" } elseif ($rows.Count) { "Medium" } else { "OK" }
    Add-Check -Id "22" -Title "SIDHistory" -Severity $sev -Data $rows `
        -Recommendation "Clean SIDHistory after migration; same-domain SIDs in SIDHistory indicate possible SIDHistory injection"
}

Invoke-Check "23" "Kerberoastable accounts" {
    $rows = @($Users | Where-Object { $_.Enabled -and $_.servicePrincipalName -and $_.SamAccountName -ne 'krbtgt' } |
        Select-Object SamAccountName, PasswordLastSet, @{ n = 'Privileged'; e = { Get-PrivGroups $_.DistinguishedName } }, @{ n = 'SPN'; e = { Join-Values $_.servicePrincipalName } })
    $sev = if (@($rows | Where-Object Privileged).Count) { "High" } elseif ($rows.Count) { "Medium" } else { "OK" }
    Add-Check -Id "23" -Title "Kerberoastable accounts" -Severity $sev -Data $rows `
        -Summary ("{0} user accounts with SPN ({1} privileged)" -f $rows.Count, @($rows | Where-Object Privileged).Count) `
        -Recommendation "Use gMSA; otherwise 25+ char passwords and AES-only (msDS-SupportedEncryptionTypes)"
}

Invoke-Check "24" "Trusts" {
    $rows = @(Get-ADTrust @AD -Filter * | ForEach-Object {
        $issues = @()
        $external = -not $_.IntraForest -and -not $_.ForestTransitive
        if ($external -and -not $_.SIDFilteringQuarantined) { $issues += "SID filtering (quarantine) disabled" }
        if ($_.ForestTransitive -and -not $_.SelectiveAuthentication) { $issues += "forest-wide authentication" }
        if (Get-Prop $_ 'TGTDelegation') { $issues += "TGT delegation enabled" }
        [pscustomobject]@{ Name = $_.Name; Direction = [string]$_.Direction; TrustType = [string]$_.TrustType; IntraForest = $_.IntraForest
            ForestTransitive = $_.ForestTransitive; SIDFilteringQuarantined = $_.SIDFilteringQuarantined; SelectiveAuthentication = $_.SelectiveAuthentication; Issues = ($issues -join "; ") }
    })
    $sev = if (@($rows | Where-Object { $_.Issues -match "SID filtering|TGT" }).Count) { "High" } elseif (@($rows | Where-Object Issues).Count) { "Low" } elseif ($rows.Count) { "Info" } else { "OK" }
    Add-Check -Id "24" -Title "Trusts" -Severity $sev -Data $rows -Recommendation "Keep SID filtering on external trusts; use selective authentication where possible; remove unused trusts"
}

Invoke-Check "25" "gMSA inventory" {
    $rows = @(Get-ADServiceAccount @AD -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, Enabled |
        Select-Object SamAccountName, Enabled, @{ n = 'AllowedToRetrieve'; e = { Join-Values $_.PrincipalsAllowedToRetrieveManagedPassword } })
    Add-Check -Id "25" -Title "gMSA inventory" -Severity Info -Data $rows -Recommendation "Restrict PrincipalsAllowedToRetrieveManagedPassword to the hosts that run the service"
}

Invoke-Check "26" "DC patch recency" {
    Add-DcCheck -Id "26" -Title "DC patch recency" -SeverityIfFound High -Recommendation "Patch DCs monthly (cumulative update within 30 days of release)" -Row {
        param($dc, $d)
        $days = if ($d.LastHotfixOn) { [int]($Now - [datetime]$d.LastHotfixOn).TotalDays } else { $null }
        [pscustomobject]@{ DC = $dc; OSBuild = $d.OSBuild; LastHotfix = $d.LastHotfix; InstalledOn = $d.LastHotfixOn; DaysAgo = $days; Compliant = ($null -ne $days -and $days -le 45) }
    }
}

Invoke-Check "27" "NTLMv1 logons observed on DCs" {
    if ($SkipDCChecks) { Add-Check -Id "27" -Title "NTLMv1 logons observed on DCs" -Severity Info -Summary "Skipped (-SkipDCChecks)"; return }
    $rows = @($DcOk | ForEach-Object { $dc = $_.DC; @($_.Data.NTLMv1) | ForEach-Object { [pscustomobject]@{ DC = $dc; Account = $_.Account; Workstation = $_.Workstation; IP = $_.IP; Count = $_.Count } } })
    $errs = @($DcOk | Where-Object { $_.Data.NTLMv1Error } | ForEach-Object { "{0}: {1}" -f $_.DC, $_.Data.NTLMv1Error })
    $sum = "{0} distinct account/source pairs in last {1}h" -f $rows.Count, $EventHours
    if ($errs) { $sum += " (read errors: $($errs -join ' | '))" }
    Add-Check -Id "27" -Title "NTLMv1 logons observed on DCs" -SeverityIfFound High -Data $rows -Summary $sum `
        -Recommendation "Remediate each source (NTLMv2/Kerberos) before enforcing LmCompatibilityLevel=5; requires 'Audit Logon' success auditing"
}

Invoke-Check "28" "Unsigned LDAP binds on DCs" {
    if ($SkipDCChecks) { Add-Check -Id "28" -Title "Unsigned LDAP binds on DCs" -Severity Info -Summary "Skipped (-SkipDCChecks)"; return }
    $rows = @($DcOk | ForEach-Object {
        $dc = $_.DC; $d = $_.Data
        $clients = @($d.Ldap2889)
        if ($clients.Count) { $clients | ForEach-Object { [pscustomobject]@{ DC = $dc; Summary2887 = $d.Ldap2887; ClientIP = $_.ClientIP; Identity = $_.Identity; Count = $_.Count } } }
        elseif ($d.Ldap2887) { [pscustomobject]@{ DC = $dc; Summary2887 = $d.Ldap2887; ClientIP = "(enable LDAP diag level 2 for 2889 detail, current=$($d.LdapDiagLevel))"; Identity = ""; Count = $null } }
    })
    Add-Check -Id "28" -Title "Unsigned LDAP binds on DCs" -SeverityIfFound High -Data $rows `
        -Recommendation "Fix clients listed in 2889 (LDAPS/signing) before requiring LDAP signing and channel binding"
}

Invoke-Check "29" "Reversible encryption" {
    $rows = @($Users | Where-Object { $_.Enabled -and $_.AllowReversiblePasswordEncryption } | ForEach-Object { [pscustomobject]@{ Scope = "User"; Name = $_.SamAccountName } })
    $ddp = Get-ADDefaultDomainPasswordPolicy @AD
    if ($ddp.ReversibleEncryptionEnabled) { $rows += [pscustomobject]@{ Scope = "Default Domain Password Policy"; Name = $Domain.DNSRoot } }
    $rows += @(Get-ADFineGrainedPasswordPolicy @AD -Filter * | Where-Object ReversibleEncryptionEnabled | ForEach-Object { [pscustomobject]@{ Scope = "Fine-grained policy"; Name = $_.Name } })
    Add-Check -Id "29" -Title "Reversible encryption" -SeverityIfFound High -Data $rows -Recommendation "Disable reversible encryption and reset affected passwords"
}

Invoke-Check "30" "Password policy (CIS)" {
    $p = Get-ADDefaultDomainPasswordPolicy @AD
    $rows = @(
        [pscustomobject]@{ Setting = "MinPasswordLength";   Current = $p.MinPasswordLength;   Recommended = ">= 14";        Compliant = ($p.MinPasswordLength -ge 14) }
        [pscustomobject]@{ Setting = "PasswordHistoryCount"; Current = $p.PasswordHistoryCount; Recommended = ">= 24";       Compliant = ($p.PasswordHistoryCount -ge 24) }
        [pscustomobject]@{ Setting = "ComplexityEnabled";   Current = $p.ComplexityEnabled;   Recommended = "True";         Compliant = [bool]$p.ComplexityEnabled }
        [pscustomobject]@{ Setting = "MaxPasswordAge";      Current = $p.MaxPasswordAge;      Recommended = "1-365 days";   Compliant = ($p.MaxPasswordAge.TotalDays -gt 0 -and $p.MaxPasswordAge.TotalDays -le 365) }
        [pscustomobject]@{ Setting = "MinPasswordAge";      Current = $p.MinPasswordAge;      Recommended = ">= 1 day";     Compliant = ($p.MinPasswordAge.TotalDays -ge 1) }
        [pscustomobject]@{ Setting = "LockoutThreshold";    Current = $p.LockoutThreshold;    Recommended = "1-5";          Compliant = ($p.LockoutThreshold -ge 1 -and $p.LockoutThreshold -le 5) }
        [pscustomobject]@{ Setting = "LockoutDuration";     Current = $p.LockoutDuration;     Recommended = ">= 15 min";    Compliant = ($p.LockoutDuration.TotalMinutes -ge 15) }
        [pscustomobject]@{ Setting = "LockoutObservationWindow"; Current = $p.LockoutObservationWindow; Recommended = ">= 15 min"; Compliant = ($p.LockoutObservationWindow.TotalMinutes -ge 15) }
    )
    $bad = @($rows | Where-Object { -not $_.Compliant })
    Add-Check -Id "30" -Title "Password policy (CIS)" -Severity $(if ($bad.Count) { "Medium" } else { "OK" }) -Data $rows `
        -Summary ("{0}/{1} settings non-compliant: {2}" -f $bad.Count, $rows.Count, (($bad | ForEach-Object Setting) -join ", ")) `
        -Recommendation "Align Default Domain Policy with CIS; use fine-grained policies for admins/service accounts"
}

Invoke-Check "31" "krbtgt password age" {
    $k = Get-ADUser @AD -Identity "$DomSid-502" -Properties PasswordLastSet
    $days = [int]($Now - $k.PasswordLastSet).TotalDays
    Add-Check -Id "31" -Title "krbtgt password age" -Severity $(if ($days -gt 180) { "Medium" } else { "OK" }) `
        -Data @([pscustomobject]@{ Account = "krbtgt"; PasswordLastSet = $k.PasswordLastSet; DaysAgo = $days }) `
        -Summary "krbtgt password changed $days days ago" -Recommendation "Rotate krbtgt twice (with replication wait in between) at least every 180 days"
}

Invoke-Check "32" "PASSWD_NOTREQD accounts" {
    $rows = @($Users | Where-Object { $_.Enabled -and $_.PasswordNotRequired } | Select-Object SamAccountName, Name, PasswordLastSet)
    Add-Check -Id "32" -Title "PASSWD_NOTREQD accounts" -SeverityIfFound Medium -Data $rows -Recommendation "Clear the flag: Set-ADAccountControl -PasswordNotRequired `$false"
}

Invoke-Check "33" "MachineAccountQuota" {
    $maq = (Get-ADObject @AD -Identity $Domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
    Add-Check -Id "33" -Title "MachineAccountQuota" -Severity $(if ($maq -gt 0) { "Medium" } else { "OK" }) -Summary "ms-DS-MachineAccountQuota = $maq" `
        -Recommendation "Set to 0 and delegate computer join to a dedicated group (blocks RBCD/noPac-style abuse)"
}

Invoke-Check "34" "AD Recycle Bin" {
    $rb = Get-ADOptionalFeature @AD -Filter "Name -eq 'Recycle Bin Feature'"
    $on = $rb -and @($rb.EnabledScopes).Count -gt 0
    Add-Check -Id "34" -Title "AD Recycle Bin" -Severity $(if ($on) { "OK" } else { "Low" }) -Summary "Enabled: $on" `
        -Recommendation "Enable-ADOptionalFeature 'Recycle Bin Feature' (irreversible, requires FFL 2008 R2+)"
}

Invoke-Check "35" "Pre-Windows 2000 Compatible Access" {
    $g = Get-ADGroup @AD -Identity "S-1-5-32-554" -Properties member
    $rows = @(@($g.member) | ForEach-Object {
        $who = switch -Regex ($_) { 'CN=S-1-1-0,' { "Everyone" } 'CN=S-1-5-7,' { "Anonymous Logon" } 'CN=S-1-5-11,' { "Authenticated Users" } default { $_ } }
        [pscustomobject]@{ Member = $who; DistinguishedName = $_ }
    })
    $sev = if (@($rows | Where-Object { $_.Member -in "Everyone", "Anonymous Logon" }).Count) { "High" } elseif (@($rows | Where-Object Member -eq "Authenticated Users").Count) { "Low" } else { "OK" }
    Add-Check -Id "35" -Title "Pre-Windows 2000 Compatible Access" -Severity $sev -Data $rows `
        -Recommendation "Remove Everyone/Anonymous Logon; evaluate removing Authenticated Users after testing legacy apps"
}

# ============================== Reporting ==============================
$Ordered = @($Results | Sort-Object @{ e = { $SevOrder[$_.Severity] }; Descending = $true }, Id)
$counts = $Results | Group-Object Severity | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }
Write-Log ("Assessment completed in {0:N1}s - {1}" -f $sw.Elapsed.TotalSeconds, ($counts -join ", "))

$Ordered | Select-Object Id, Title, Severity, Count, Summary, Recommendation, @{ n = 'Csv'; e = { Split-Path $_.Csv -Leaf } } |
    Export-Csv -Path (Join-Path $OutputPath "summary.csv") -NoTypeInformation -Encoding UTF8

# --- TXT (single encoding, wide tables) ---
$txt = New-Object System.Text.StringBuilder
[void]$txt.AppendLine("ACTIVE DIRECTORY HARDENING REPORT")
[void]$txt.AppendLine(("Domain: {0} | Forest: {1} | DC queried: {2} | Generated: {3}" -f $Domain.DNSRoot, $Forest.Name, $Server, $Now))
[void]$txt.AppendLine(("Results: {0}" -f ($counts -join ", ")))
[void]$txt.AppendLine("")
[void]$txt.AppendLine(($Ordered | Format-Table Id, Severity, Title, Count, Summary -AutoSize | Out-String -Width 400))
foreach ($r in ($Results | Sort-Object Id)) {
    [void]$txt.AppendLine(("=" * 100))
    [void]$txt.AppendLine(("[{0}] {1} - {2}" -f $r.Id, $r.Title, $r.Severity))
    [void]$txt.AppendLine("Summary: $($r.Summary)")
    if ($r.Recommendation) { [void]$txt.AppendLine("Recommendation: $($r.Recommendation)") }
    if ($r.Count) {
        [void]$txt.AppendLine(($r.Data | Select-Object -First 50 | Format-Table -AutoSize | Out-String -Width 400))
        if ($r.Count -gt 50) { [void]$txt.AppendLine("... $($r.Count - 50) more rows in csv\$(Split-Path $r.Csv -Leaf)") }
    }
}
$txt.ToString() | Out-File -FilePath (Join-Path $OutputPath "AD_Hardening_Report.txt") -Encoding UTF8

# --- HTML ---
$colors = @{ Error = "#7b2cbf"; High = "#d62828"; Medium = "#f77f00"; Low = "#2a9d8f"; Info = "#6c757d"; OK = "#2b9348" }
$h = New-Object System.Text.StringBuilder
[void]$h.Append(@"
<!DOCTYPE html><html><head><meta charset="utf-8"/><title>AD Hardening Report - $(ConvertTo-HtmlSafe $Domain.DNSRoot)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}
table{border-collapse:collapse;width:100%;margin:8px 0 20px 0;font-size:13px}
th,td{border:1px solid #ddd;padding:5px 7px;text-align:left;vertical-align:top}
th{background:#f4f4f4}
.sev{color:#fff;padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px}
details{border:1px solid #e5e5e5;border-radius:6px;padding:8px 12px;margin:8px 0}
summary{cursor:pointer;font-weight:600}
.small{color:#666;font-size:12px}
</style></head><body>
<h1>Active Directory Hardening Report</h1>
<p class="small">Domain: $(ConvertTo-HtmlSafe $Domain.DNSRoot) - Forest: $(ConvertTo-HtmlSafe $Forest.Name) - DC queried: $(ConvertTo-HtmlSafe $Server) - Generated: $Now</p>
<p>$(ConvertTo-HtmlSafe ($counts -join ', '))</p>
<table><tr><th>Id</th><th>Severity</th><th>Check</th><th>Count</th><th>Summary</th><th>Recommendation</th></tr>
"@)
foreach ($r in $Ordered) {
    [void]$h.AppendFormat("<tr><td>{0}</td><td><span class='sev' style='background:{1}'>{2}</span></td><td><a href='#c{0}'>{3}</a></td><td>{4}</td><td>{5}</td><td>{6}</td></tr>`n",
        $r.Id, $colors[$r.Severity], $r.Severity, (ConvertTo-HtmlSafe $r.Title), $r.Count, (ConvertTo-HtmlSafe $r.Summary), (ConvertTo-HtmlSafe $r.Recommendation))
}
[void]$h.Append("</table>`n")
foreach ($r in ($Ordered | Where-Object Count)) {
    [void]$h.AppendFormat("<details id='c{0}'><summary>[{0}] {1} ({2})</summary>", $r.Id, (ConvertTo-HtmlSafe $r.Title), $r.Count)
    $cols = @($r.Data[0].PSObject.Properties.Name)
    [void]$h.Append("<table><tr>"); foreach ($c in $cols) { [void]$h.Append("<th>$(ConvertTo-HtmlSafe $c)</th>") }; [void]$h.Append("</tr>")
    foreach ($row in ($r.Data | Select-Object -First 200)) {
        [void]$h.Append("<tr>"); foreach ($c in $cols) { [void]$h.Append("<td>$(ConvertTo-HtmlSafe $row.$c)</td>") }; [void]$h.Append("</tr>")
    }
    [void]$h.Append("</table>")
    if ($r.Count -gt 200) { [void]$h.Append("<p class='small'>First 200 rows shown - full list in csv\$(ConvertTo-HtmlSafe (Split-Path $r.Csv -Leaf))</p>") }
    [void]$h.Append("</details>`n")
}
[void]$h.Append("</body></html>")
$h.ToString() | Out-File -FilePath (Join-Path $OutputPath "AD_Hardening_Report.html") -Encoding UTF8

# --- XLSX (optional, no auto-install on a Tier 0 host) ---
if ($Excel) {
    if (Get-Module -ListAvailable -Name ImportExcel) {
        Import-Module ImportExcel
        $xlsx = Join-Path $OutputPath "AD_Hardening_Report.xlsx"
        $Ordered | Select-Object Id, Severity, Title, Count, Summary, Recommendation | Export-Excel -Path $xlsx -WorksheetName "Summary" -AutoSize -FreezeTopRow -BoldTopRow
        foreach ($r in ($Ordered | Where-Object Count)) {
            $ws = ("{0} {1}" -f $r.Id, ($r.Title -replace '[\[\]\*\?/\\:]', '')); if ($ws.Length -gt 31) { $ws = $ws.Substring(0, 31) }
            $r.Data | Export-Excel -Path $xlsx -WorksheetName $ws -AutoSize -FreezeTopRow -BoldTopRow
        }
        Write-Log "Excel report: $xlsx"
    } else {
        Write-Log "ImportExcel not installed: XLSX skipped (Install-Module ImportExcel -Scope CurrentUser on an admin workstation)" "WARN"
    }
}

Write-Log "Reports written to $OutputPath"
Write-Host ""
$Ordered | Where-Object { $_.Severity -in "Error", "High", "Medium" } | Format-Table Id, Severity, Title, Summary -AutoSize | Out-String -Width 220 | Write-Host

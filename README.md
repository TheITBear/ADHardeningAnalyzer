# 🛡️ AD Hardening Analyzer

Read-only PowerShell assessment of **Active Directory hardening and security posture**, based on CIS Benchmarks, Microsoft security baselines and common AD attack paths (Kerberoasting, AS-REP roasting, delegation abuse, NTLMv1, unsigned LDAP, SIDHistory, etc.).

> The script **never changes** AD or domain controllers: it only reads and reports.

---

## 📂 Contents

| File | Description |
|------|-------------|
| `scripts/AD-Hardening-Analyzer.ps1` | Single non-interactive analyzer (36 checks, TXT/HTML/CSV/XLSX output) |

---

## 🧰 Requirements

- Windows PowerShell **5.1+**
- **RSAT**: `ActiveDirectory` module (required), `GroupPolicy` module (optional, for GPO checks)
- **WinRM** reachable on all domain controllers (DC checks run remotely, in parallel)
- Account with read access to AD and **local admin rights on DCs** (registry, services, Security / Directory Service event logs) — typically a Tier 0 admin account from a PAW
- Optional: `ImportExcel` module for the `-Excel` output (not auto-installed)

---

## 🚀 Usage

```powershell
# Full assessment (output on Desktop\ADHardening_<timestamp>)
.\scripts\AD-Hardening-Analyzer.ps1

# Custom thresholds, 3 days of events, Excel workbook
.\scripts\AD-Hardening-Analyzer.ps1 -InactiveDays 60 -EventHours 72 -Excel

# AD-only (no WinRM to DCs)
.\scripts\AD-Hardening-Analyzer.ps1 -SkipDCChecks -OutputPath D:\Audit
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-OutputPath` | `Desktop\ADHardening_<timestamp>` | Output folder |
| `-Server` | PDC emulator | DC used for AD queries |
| `-InactiveDays` | 90 | Inactive users/computers threshold |
| `-EventHours` | 24 | Look-back window for DC event analysis |
| `-MaxEvents` | 5000 | Max events read per DC per query |
| `-SkipDCChecks` | off | Skip remote DC checks |
| `-Excel` | off | Also write an XLSX (requires ImportExcel) |
| `-ThrottleLimit` | 16 | Parallel WinRM connections |
| `-ConnectTimeoutSec` / `-OperationTimeoutSec` | 15 / 300 | WinRM timeouts |

### 📁 Output

```
ADHardening_YYYYMMDD_HHmmss\
├─ AD_Hardening_Report.html   # summary + per-check details, sorted by severity
├─ AD_Hardening_Report.txt
├─ AD_Hardening_Report.xlsx   # with -Excel
├─ GPO_Report.html
├─ summary.csv
├─ run.log
└─ csv\NN_<check>.csv          # affected objects for each check
```

Severity levels: **High / Medium / Low / Info / OK / Error** (a failing check is reported as *Error* and never stops the run).

---

## ✅ Checks

| # | Check | Scope |
|---|-------|-------|
| 00 | DC reachability (WinRM) | DCs |
| 01 | Inactive users | AD |
| 02 | Inactive computers | AD |
| 03 | Privileged group membership (recursive, resolved by SID) | AD |
| 04 | Password never expires (privileged flagged High) | AD |
| 05 | Orphaned `adminCount=1` | AD |
| 06 | OU structure / protection from accidental deletion | AD |
| 07 | Unsupported OS (XP→8.1, Server ≤ 2012 R2, Windows 10 EOL) | AD |
| 08 | SMBv1 / SMB signing | DCs |
| 09 | NTLM `LmCompatibilityLevel` | DCs |
| 10 | LDAP signing / channel binding (`LdapEnforceChannelBinding`) | DCs |
| 11 | Print Spooler | DCs |
| 12 | Firewall profiles + listening TCP ports | DCs |
| 13 | GPO HTML export | GPO |
| 14 | LSASS `RunAsPPL` | DCs |
| 15 | LAPS coverage (legacy + Windows LAPS) | AD |
| 16 | AS-REP roastable accounts | AD |
| 17 | Duplicate SPNs | AD |
| 18 | Privileged account protections (Protected Users, not delegable, PAW restriction, password age, SPN) | AD |
| 19 | Kerberos delegation (unconstrained / protocol transition / constrained) | AD |
| 20 | Resource-based constrained delegation | AD |
| 21 | GPO edit permissions for non-default trustees | GPO |
| 22 | SIDHistory (same-domain SID = possible injection) | AD |
| 23 | Kerberoastable accounts | AD |
| 24 | Trusts (SID filtering, selective auth, TGT delegation) | AD |
| 25 | gMSA inventory | AD |
| 26 | DC patch recency | DCs |
| 27 | NTLMv1 logons observed (Event 4624 `LmPackageName`) | DCs |
| 28 | Unsigned LDAP binds (Events 2887 / 2889) | DCs |
| 29 | Reversible encryption (users, domain policy, FGPP) | AD |
| 30 | Password & lockout policy vs CIS | AD |
| 31 | krbtgt password age | AD |
| 32 | `PASSWD_NOTREQD` accounts | AD |
| 33 | `ms-DS-MachineAccountQuota` | AD |
| 34 | AD Recycle Bin | AD |
| 35 | Pre-Windows 2000 Compatible Access | AD |

---

## 📝 Changelog

### v2.0
- **Unified** the two scripts into one non-interactive analyzer (`AD-Hardening-Analyzer.ps1`).
- **Fixed** DC-scoped checks (SMBv1, NTLM, LDAP, Spooler, firewall, RunAsPPL, hotfix) that only inspected the *local* machine: they now run on **all DCs in parallel** via WinRM.
- **Fixed** mixed report encoding (PS 5.1 `Out-File -Append` defaults to UTF-16) and truncated tables.
- **Fixed** logic bugs: adminCount filter (`-notmatch` on an array), legacy OS regex missing `Windows Server 2008/2012`, inactive computers missing `OperatingSystem`, 4624 "multiple IP" filter always true, duplicated delegation checks, `Get-GPPermission` by name.
- **Removed** the non-functional Excel/Word prompts (modules were installed but never used; the `Word` module does not exist). XLSX is now generated with `-Excel`.
- **Faster**: AD users/computers are read once (previously `Get-ADUser -Filter *` ran 9 times); recursive group membership via `LDAP_MATCHING_RULE_IN_CHAIN`.
- **New** checks: Kerberoasting, RBCD, NTLMv1 sources, unsigned LDAP clients, krbtgt age, MachineAccountQuota, PASSWD_NOTREQD, password policy vs CIS, Recycle Bin, Pre-Windows 2000 access, trusts hardening.

---

## 🔒 License

Released under the [MIT License](./LICENSE).

© 2025 – TheITBear

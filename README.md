# 🛡️ Active Directory Hardening Toolkit

This repository contains a set of PowerShell scripts to automate the assessment of Active Directory hardening and security posture, based on best practices from CIS Benchmarks, Microsoft, and enterprise-level security standards.

---

## 📂 Contents

| File                                | Description                                          |
|-------------------------------------|------------------------------------------------------|
| `AD_Hardening_Report_Script.ps1`    | Interactive script with 16 baseline hardening checks |
| `AD_Hardening_Advanced_Checks.ps1`  | 12 advanced audit blocks for deep AD inspection      |
| `Esegui_AD_Hardening.bat`           | Windows launcher for simplified execution           |
| `AD_Hardening_Report_Script.txt`    | Readable version of the full `.ps1` base script      |

---

## 🧰 Requirements

- Run as **Administrator**
- Requires **RSAT: ActiveDirectory** PowerShell module
- Optional (for extra features):
  - `ImportExcel` (Excel output)
  - `Word` module (Word `.docx` report generation)

Install modules if missing:
```powershell
Install-Module -Name ImportExcel -Scope CurrentUser -Force
Install-Module -Name Word -Scope CurrentUser -Force
```

---

## 🚀 How to Use

1. **Extract the ZIP package**
2. **Right-click `Esegui_AD_Hardening.bat` and run as Administrator**
3. Follow the interactive prompts
4. Reports will be saved to your Desktop:
   - `AD_Hardening_Report.txt`
   - Optional: `.csv`, `.docx`, `.html`

---

## ✅ Base Checks (Script 1–16)

- Inactive users/computers
- Privileged group and user analysis
- Password policy (Never expires)
- AdminCount misuse
- OU structure dump
- Obsolete OS detection
- SMBv1 / NTLM / LDAP Signing checks
- Print Spooler / Firewall state
- GPO report in HTML
- LSASS PPL and LAPS status

---

## 🔍 Advanced Checks (Script 17–28)

- AS-REP Roasting risks (PreAuth disabled)
- Duplicate SPNs
- Unrestricted logonWorkstations
- Kerberos delegation (unconstrained/constrained)
- ACL audits on GPOs and OUs
- SIDHistory tracing
- Domain trust validation
- gMSA enumeration
- Hotfix recency (patch status)
- Anomalous logon IP analysis
- Reversible password detection

---

## 🔒 License

This toolkit is released for internal use under the [MIT License](https://opensource.org/licenses/MIT).

© 2025 – TheITBear – All rights reserved.

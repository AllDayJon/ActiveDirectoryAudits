# Active Directory Audit Scripts

This repository contains scripts designed for auditing and reporting on various aspects of Active Directory (AD) environments. These scripts are intended to enhance security, manageability, and overall health of AD infrastructures.

## Script Descriptions

### Active Directory Audit Script

The primary script in this repository is an Active Directory Audit Script. It performs an extensive audit of an Active Directory environment, covering key areas such as account status, group memberships, password policies, and more. 

#### Features

- **Stale Account Detection:** Identifies accounts that have not logged in for over 30 days.
- **Aged Passwords Report:** Finds accounts with passwords unchanged for over 120 days.
- **Privileged Group Membership Enumeration:** Lists members in high-privileged groups like Domain Admins.
- **Empty Group Identification:** Detects security groups without members.
- **Inactive User and Computer Accounts Reporting:** Reports on user and computer accounts that have been inactive for a specified period.
- **Orphaned SID History Analysis:** Identifies accounts with SID histories from non-existent domains.
- **Large Kerberos Token Users Highlighting:** Flags users with a high number of group memberships.
- **UAC Risk Accounts Identification:** Finds accounts with risky User Account Control settings.

### Installation

Clone the repository using:

```bash
git clone https://github.com/your-username/active-directory-audit.git
```

### Usage

To execute the Active Directory Audit Script, navigate to the script directory and run:
```bash
.\ADAudit.ps1 -DomainController "YourDomainController"
```

Replace "YourDomainController" with the actual domain controller's name or IP address.

### Prerequisites

- PowerShell 5.0 or higher.
- Active Directory module for PowerShell.
- Appropriate permissions to perform read operations on the Active Directory.

### Disclaimer

These scripts are provided "as is" for informational purposes. Please review and test thoroughly before deploying in a production environment.

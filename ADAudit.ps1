<#
.SYNOPSIS
    Active Directory Audit Script

.DESCRIPTION
    This script audits various aspects of Active Directory (AD) to enhance security and cleanliness. It checks for stale accounts, password policies, privileged group memberships, and other potential security risks. Each section of the script addresses specific AD components, providing insights into areas often overlooked in routine audits.

    The script includes functions to:
    - Identify accounts not logged in for over 30 days (potential security risks or resource wastage).
    - Find accounts with passwords not changed in over 120 days (violating typical security best practices).
    - Enumerate members in privileged groups (to manage elevated access rights).
	NOTE: Group membership is not recursive, so nested group members are not included in the count. This is complex enough to warrant a separate script to enumerate nested group members.
    - Detect empty security groups (for cleanup and management).
    - Report on inactive user and computer accounts (identifying unused accounts or systems).
    - List accounts with SID histories from non-existent domains (migration leftovers, security concerns).
    - Highlight users with large Kerberos token sizes (potential cause of authentication issues).
    - Identify accounts with risky User Account Control settings (like 'Password not required' or 'Password never expires').

    Author: Jon Aslanian

.EXAMPLE
    .\AD_Audit_Script.ps1 -DomainController "dc1.example.com"
    Executes the script and generates a detailed AD audit report, targeting the specified domain controller.

.NOTES
    Ensure you have the necessary permissions and that the Active Directory module is available. Testing the script in a non-production environment is recommended before deploying it in a live setting.

.PARAMETER DomainController
    The domain controller to target for the Active Directory queries. This parameter allows the script to be used flexibly in different AD environments.

#>


Import-Module ActiveDirectory


# Main execution block
function Generate-ADReport {
    param (
        [string]$DomainController
    )

	

    Write-Host "Generating Active Directory Audit Report..." -ForegroundColor Cyan



	function Get-EmptyGroups {
		param ([string]$DomainController)
	
		$allGroups = Get-ADGroup -Filter * -Server $DomainController
		$emptyGroups = @()
	
		foreach ($group in $allGroups) {
			try {
				$groupMembers = Get-ADGroupMember -Identity $group -Server $DomainController -ErrorAction Stop
				if (-not $groupMembers) {
					$emptyGroups += $group
				}
			} catch {
				Write-Host "Error processing group $($group.Name): $($_.Exception.Message)" -ForegroundColor Red
			}
		}
	
		$emptyGroups | Select-Object Name
	}
	

	function Get-InactiveUserAccounts {
		$inactiveDate = (Get-Date).AddDays(-180) # Example: 180 days
		Get-ADUser -Filter 'LastLogonDate -lt $inactiveDate' -Properties LastLogonDate -Server $DomainController |
		Select-Object Name, LastLogonDate
	}
	
	function Get-InactiveComputerAccounts {
		$inactiveDate = (Get-Date).AddDays(-180) # Example: 180 days
		Get-ADComputer -Filter 'LastLogonDate -lt $inactiveDate' -Properties LastLogonDate -Server $DomainController |
		Select-Object Name, LastLogonDate
	}
	
	
	function Get-OrphanedSIDHistory {
		Get-ADUser -Filter * -Properties sidHistory -Server $DomainController | Where-Object { $_.sidHistory } |
		Select-Object Name, sidHistory
	}
	
	function Get-LargeKerberosTokenUsers {
		Get-ADUser -Filter * -Properties MemberOf -Server $DomainController | Where-Object { $_.MemberOf.Count -gt 50 } |
		Select-Object Name, @{Name="GroupCount";Expression={$_.MemberOf.Count}}
	}
	
	
	function Get-UACRiskAccounts {
		param (
			[bool]$CheckPasswdNotReqd = $true,
			[bool]$CheckDontExpirePasswd = $true,
			[bool]$CheckTrustedForDelegation = $true
		)
	

		$uacFilterParts = @()
		if ($CheckPasswdNotReqd) {
			$uacFilterParts += "UserAccountControl -band 32"
		}
		if ($CheckDontExpirePasswd) {
			$uacFilterParts += "UserAccountControl -band 65536"
		}
		if ($CheckTrustedForDelegation) {
			$uacFilterParts += "UserAccountControl -band 4194304"
		}
		
		$uacFilter = $uacFilterParts -join " -or "
	
		$users = Get-ADUser -Filter $uacFilter -Properties Name, UserAccountControl -Server $DomainController
	
		$users | ForEach-Object {
			$uacFlags = @()
			if ($CheckPasswdNotReqd -and ($_.UserAccountControl -band 32)) {
				$uacFlags += "PASSWD_NOTREQD (Password not required)"
			}
			if ($CheckDontExpirePasswd -and ($_.UserAccountControl -band 65536)) {
				$uacFlags += "DONT_EXPIRE_PASSWD (Password never expires)"
			}
			if ($CheckTrustedForDelegation -and ($_.UserAccountControl -band 4194304)) {
				$uacFlags += "TRUSTED_FOR_DELEGATION (Account trusted for Kerberos delegation)"
			}
	
			[PSCustomObject]@{
				Name = $_.Name
				UserAccountControl = $_.UserAccountControl
				UACFlagsDescription = $uacFlags -join ', '
			}
		} | Select-Object Name, UserAccountControl, UACFlagsDescription
	}
	
	# Function to get accounts enabled with last login more than 30 days ago
	function Get-StaleAccounts {
		$date = (Get-Date).AddDays(-30)
		Get-ADUser -Filter 'Enabled -eq $true -and LastLogonDate -lt $date' -Properties LastLogonDate -Server $DomainController |
		Select-Object Name, LastLogonDate
	}


	# Function to get accounts with passwords not changed in more than 120 days
	function Get-AgedPasswords {
		$date = (Get-Date).AddDays(-120).ToString("yyyy-MM-dd")
		Get-ADUser -Filter "PasswordLastSet -lt '$date'" -Properties PasswordLastSet -Server $DomainController |
		Select-Object Name, PasswordLastSet
	}


# Function to get unique count of members in privileged roles
	function Get-PrivilegedGroupMembers {
		$privilegedGroups = @("Enterprise Admins", "Schema Admins", "Domain Admins", "Account Operators", "Server Operators", "Print Operators", "DHCP Administrators", "DNSAdmins")
		$groupMembers = @{}

		foreach ($group in $privilegedGroups) {
			$groupObject = Get-ADGroup -Filter "Name -eq '$group'" -Server $DomainController -ErrorAction SilentlyContinue
			if ($groupObject) {
				$groupMembers[$group] = (Get-ADGroupMember -Identity $group -Server $DomainController).Count
			}
		}

		return $groupMembers
	}
	
	# Define all the sections of the report
	$reportSections = @(
		@{Title="Stale Accounts"; Function="Get-StaleAccounts"},
		@{Title="Accounts with Aged Passwords"; Function="Get-AgedPasswords"},
		@{Title="Privileged Group Members"; Function="Get-PrivilegedGroupMembers"},
		@{Title="Empty Groups"; Function="Get-EmptyGroups"},
		@{Title="Inactive User Accounts"; Function="Get-InactiveUserAccounts"},
		@{Title="Inactive Computer Accounts"; Function="Get-InactiveComputerAccounts"},
		@{Title="Orphaned SID History"; Function="Get-OrphanedSIDHistory"},
		@{Title="Large Kerberos Token Users"; Function="Get-LargeKerberosTokenUsers"},
		@{Title="UAC Risk Accounts"; Function="Get-UACRiskAccounts"}
	)

	# Initialize progress bar variables
	$totalSections = $reportSections.Length
	$currentSectionIndex = 0

    # Loop through each report section and gather data
    foreach ($section in $reportSections) {
        # Update the progress bar
        $currentSectionIndex++
        $statusMessage = "Processing $($section.Title)"
        Write-Progress -Activity "Generating Report" -Status $statusMessage -PercentComplete (($currentSectionIndex / $totalSections) * 100)

        # Display current section status
        Write-Host "Processing section: $($section.Title)" -ForegroundColor Yellow

        # Invoke the function for each section and gather data
        $functionName = $section.Function
        $sectionData = & $functionName -DomainController $DomainController

        # Display a summary of the current section's results
        Write-Host "Processed $($sectionData.Count) items in $($section.Title)." -ForegroundColor Green

        # Store the data
        $section.Data = $sectionData
    }

  # Combine and export all data into a single CSV file
  $csvData = foreach ($section in $reportSections) {
	  foreach ($item in $section.Data) {
		  [PSCustomObject]@{
			  Section = $section.Title
			  Name = $item.Name
			  Details = $item | Select-Object -ExcludeProperty Name | ConvertTo-Json -Compress
		  }
	  }
  }

  $csvData | Export-Csv -Path "AD_Audit_Report.csv" -NoTypeInformation
  Write-Host "Exported to CSV: AD_Audit_Report.csv" -ForegroundColor Yellow

  Write-Host "`nActive Directory Audit Report Generation Complete!" -ForegroundColor Green
}

# Call the main function to generate the report
# Example: Generate-ADReport -DomainController "dc1.example.com"

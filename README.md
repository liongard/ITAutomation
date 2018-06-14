# ITAutomation
Freely available set of scripts to help with automating your IT infrastructure.

## Contents
* Get-DocHealthCheck.ps1
* active-directory/Get-BasicInformation.ps1
* office365/Get-BasicInformation.ps1

### Get-DocHealthCheck.ps1

  To run the powershell script, you simply `cd` into the directory the script is at:
  `.\Get-DocHealthCheck.ps1`

  The script will prompt you for several inputs that will allow access to the ConnectWise API.
  Please note the user's API keys you specify must have READ access to Companies/Configurations
  and System/Audittrail at a minimum.

### active-directory/Get-BasicInformation.ps1
  
  To run the powershell script, you must meet the following pre-requesites:

  Active Directory Tools must be installed. Run the command below from an Administrator
  PowerShell Windows (e.g., right-click and Run As Administrator).

  `Add-WindowsFeature RSAT-AD-PowerShell,RSAT-AD-AdminCenter`

  If the script is not being run from the Domain Controller itself, other tools must
  also be installed:

  `Install-WindowsFeature -Name GPMC,RSAT-ADDS-Tools,RSAT-DNS-Server`

  If you are not running the script directly on the Domain Controller then we suggest you
  provision a service account, or use an existing one which is in the Domain Admins security
  group to retrieve the full set of data.

  To run the powershell script, you simply `cd` into the directory the script is at:
  `.\AD\Get-BasicInformation.ps1`

  The script will not prompt for any inputs by default but if you wish to run this script
  remotely you can provide the following inputs:

  * ADServer - The computer name of the Domain Controller
  * AdminUsername - The admin username to login to the remote computer with
  * AdminPassword - The associated admin password with the username

### office365/Get-BasicInformation.ps1

  To run the powershell script, you must meet the following pre-requesites:

  * Microsoft Online Services Sign-In Assistant must be installed.
  * Windows Azure Active Directory Modules must be installed.

  The script will prompt you for your admin username and password for Office 365, please
  note the script is only setup to target a single Tenant, so the username/password
  must be one associated with a single account. CSP credentials may not work or be able
  to pull back the full set of information. 
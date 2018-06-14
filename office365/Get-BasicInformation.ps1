[CmdletBinding()]
Param(
  [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
  [string]$AdminUsername,

  [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
  [string]$AdminPassword
)

Import-Module MSOnline

Function Get-CommandResult {
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
      [scriptblock]$Command
  )

  $output = @{}
  try {
      $output = $Command.invoke();
  }
  catch {
      Write-Host "Command $Command failed. Exception: $($_.Exception.Message)"
  }
  return $output;
}

Write-Host "Removing any extraneous Powershell sessions"
Get-PSSession | Remove-PSSession

# Cred object used by multiple cmdlets
$securePwStr = $AdminPassword | ConvertTo-SecureString -AsPlainText -Force
$AdminCredential = New-Object System.Management.Automation.PSCredential($AdminUsername, $securePwStr)

# Connect to Azure AD
Write-Host "Running Connect-MsolService"
Connect-MsolService -Credential $AdminCredential;

$CompanyInfo = Get-CommandResult {Get-MsolCompanyInformation}
$Users = Get-CommandResult {Get-MsolUser -All -EnabledFilter EnabledOnly | Where-Object {($_.UserPrincipalName -notlike "*#EXT#*")}}

$Report = "OFFICE 365`r`n"
$Report += "Company Name: $($CompanyInfo.DisplayName)`r`n"
$Report += "Address: $($CompanyInfo.Street)`r`n"
$Report += "City: $($CompanyInfo.City)`r`n"
$Report += "State: $($CompanyInfo.State)`r`n"
$Report += "Postal Code: $($CompanyInfo.PostalCode)`r`n"
$Report += "Country: $($CompanyInfo.CountryLetterCode)`r`n"
$Report += "Preferred Language: $($CompanyInfo.PreferredLanguage)`r`n"

$Report += "`r`n`r`nUSER/DEVICE COUNT`r`n"
$UserStats = @{
  ActiveUserCount = 0
  LicensedUserCount = 0
  UnlicensedUserCount = 0
  DisabledUserCount = 0
}
$Users | foreach {
  If (!$_.BlockCredential) {
    $UserStats.ActiveUserCount += 1
  } Else {
    $UserStats.DisabledUserCount += 1
  }

  If ($_.IsLicensed) {
    $UserStats.LicensedUserCount += 1
  } Else {
    $UserStats.UnlicensedUserCount += 1
  }
}

$Report += "Active User Count: $($UserStats.ActiveUserCount)`r`n"
$Report += "Licensed User Count: $($UserStats.LicensedUserCount)`r`n"
$Report += "Unlicensed User Count: $($UserStats.UnlicensedUserCount)`r`n"
$Report += "Disabled User Count: $($UserStats.DisabledUserCount)`r`n"

$Report += "`r`n`r`SYNCING`r`n"
$Report += "Directory Sync Enabled: $($CompanyInfo.DirectorySynchronizationEnabled)`r`n"
$Report += "Last Directory Sync Time: $($CompanyInfo.LastDirSyncTime)`r`n"
$Report += "Password Sync Enabled: $($CompanyInfo.PasswordSynchronizationEnabled)`r`n"
$Report += "Last Password Sync Time: $($CompanyInfo.LastPasswordSyncTime)`r`n"
$Report += "Directory Sync Service Account: $($CompanyInfo.DirSyncServiceAccount)`r`n"
$Report += "Directory Sync Client Version: $($CompanyInfo.DirSyncClientVersion)`r`n"
$Report += "Directory Sync Client Machine Name: $($CompanyInfo.DirSyncClientMachineName)`r`n"
$Report += "Directory Sync Application Type: $($CompanyInfo.DirSyncApplicationType)`r`n"

$Report += "`r`n`r`LICENSES`r`n"

$LicenseStats = @{
  Total = 0
  BE = 0
  BP = 0
  E3 = 0
  EME3 = 0
  EO = 0
  Other = 0
}

$UserLicenseReport = ""
$Users | foreach {
  $User = $_

  $_.Licenses | foreach {
    $LicenseStats.Total += 1

    $UserLicenseReport += 

    $_.AccountSku | foreach {
      $LicenseName = "Other"
      If ($_.SkuPartNumber -like '*O365_BUSINESS_ESSENTIALS*') {
        $LicenseStats.BE += 1
        $LicenseName = "Office 365 Business Essentials"
      }
      ElseIf ($_.SkuPartNumber -like '*O365_BUSINESS_PREMIUM*') {
        $LicenseStats.BP += 1
        $LicenseName = "Office 365 Business Premium"
      }
      ElseIf ($_.SkuPartNumber -like '*ENTERPRISEPACK*') {
        $LicenseStats.E3 += 1
        $LicenseName = "Enterprise E3"
      }
      ElseIf ($_.SkuPartNumber -like '*EMS*') {
        $LicenseStats.EME3 += 1
        $LicenseName = "Enterprise Mobility + Security E3"
      }
      ElseIf ($_.SkuPartNumber -like '*EXCHANGESTANDARD*') {
        $LicenseStats.EO += 1
        $LicenseName = "Exchange Online"
      }
      Else {
        $LicenseStats.Other += 1
      }

      If ($_.SkuPartNumber -ne "") {
        $UserLicenseReport += $User.DisplayName + "," + $User.SignInName + "," + $LicenseName + "`r`n"
      }
    }
  }
}

$Report += "Total: $($LicenseStats.Total)`r`n"
$Report += "Office 365 Business Essentials: $($LicenseStats.BE)`r`n"
$Report += "Office 365 Business Premium: $($LicenseStats.BP)`r`n"
$Report += "Enterprise E3: $($LicenseStats.E3)`r`n"
$Report += "Enterprise Mobility + Security E3: $($LicenseStats.EME3)`r`n"
$Report += "Exchange Online: $($LicenseStats.EO)`r`n"
$Report += "Other: $($LicenseStats.Other)`r`n"

$Report += "`r`n`r`n"
$Report += $UserLicenseReport

$now = $(Get-Date).tostring("MM-dd-yyyy")
$Report | Out-File -FilePath "Office365-Report-$($now).txt" -Encoding UTF8


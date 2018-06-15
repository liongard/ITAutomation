[CmdletBinding()]
Param(
  [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
  [string]$ADServer,

  [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
  [string]$AdminUsername,

  [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
  [string]$AdminPassword
)

Import-Module ActiveDirectory

# https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
$UserProps = @(
  "AccountExpirationDate",
  "AccountLockoutTime",
  "AccountNotDelegated",
  "AllowReversiblePasswordEncryption",
  "BadLogonCount",
  "CannotChangePassword",
  "CanonicalName",
  "Certificates",
  # "ChangePasswordAtLogon",
  "City",
  "CN",
  "Company",
  "Country",
  "Created",
  "Deleted",
  "Department",
  "Description",
  "DisplayName",
  "DistinguishedName",
  "Division",
  "DoesNotRequirePreAuth",
  "EmailAddress",
  "EmployeeID",
  "EmployeeNumber",
  "Enabled",
  "Fax",
  "GivenName",
  "HomeDirectory",
  "HomedirRequired",
  "HomeDrive",
  "HomePage",
  "HomePhone",
  "Initials",
  "LastBadPasswordAttempt",
  "LastKnownParent",
  "LastLogonDate",
  "LockedOut",
  "LogonWorkstations",
  "Manager",
  "MemberOf",
  "MNSLogonAccount",
  "MobilePhone",
  "Modified",
  "Name",
  "ObjectCategory",
  "ObjectClass",
  "ObjectGUID",
  "Office",
  "OfficePhone",
  "Organization",
  "OtherName",
  "PasswordExpired",
  "PasswordLastSet",
  "PasswordNeverExpires",
  "PasswordNotRequired",
  "POBox",
  "PostalCode",
  "PrimaryGroup",
  "ProfilePath",
  "ProtectedFromAccidentalDeletion",
  "SamAccountName",
  "ScriptPath",
  "ServicePrincipalNames",
  "SID",
  "SIDHistory",
  "SmartcardLogonRequired",
  "State",
  "StreetAddress",
  "Surname",
  "Title",
  "TrustedForDelegation",
  "TrustedToAuthForDelegation",
  "UseDESKeyOnly",
  "UserPrincipalName"
);

# https://social.technet.microsoft.com/wiki/contents/articles/12079.active-directory-get-adgroup-default-and-extended-properties.aspx
$GroupProps = @(
  "CanonicalName",
  "CN",
  "Created",
  "Deleted",
  "Description",
  "DisplayName",
  "DistinguishedName",
  "GroupCategory",
  "GroupScope",
  "HomePage",
  "LastKnownParent",
  "ManagedBy",
  "MemberOf",
  "Members",
  "Modified",
  "Name",
  "ObjectCategory",
  "ObjectClass",
  "ObjectGUID",
  "ProtectedFromAccidentalDeletion",
  "SamAccountName",
  "SID",
  "SIDHistory"
);

# https://social.technet.microsoft.com/wiki/contents/articles/12056.active-directory-get-adcomputer-default-and-extended-properties.aspx
$ComputerProps = @(
  "AccountExpirationDate",
  "AccountLockoutTime",
  "AccountNotDelegated",
  "AllowReversiblePasswordEncryption",
  "BadLogonCount",
  "CannotChangePassword",
  "CanonicalName",
  "Certificates",
  "CN",
  "Created",
  "Deleted",
  "Description",
  "DisplayName",
  "DistinguishedName",
  "DNSHostName",
  "DoesNotRequirePreAuth",
  "Enabled",
  "HomedirRequired",
  "HomePage",
  "IPv4Address",
  "IPv6Address",
  "LastBadPasswordAttempt",
  "LastKnownParent",
  "LastLogonDate",
  "Location",
  "LockedOut",
  "ManagedBy",
  "MemberOf",
  "MNSLogonAccount",
  "Modified",
  "Name",
  "ObjectCategory",
  "ObjectClass",
  "ObjectGUID",
  "OperatingSystem",
  "OperatingSystemHotfix",
  "OperatingSystemServicePack",
  "OperatingSystemVersion",
  "PasswordExpired",
  "PasswordLastSet",
  "PasswordNeverExpires",
  "PasswordNotRequired",
  "PrimaryGroup",
  "ProtectedFromAccidentalDeletion",
  "SamAccountName",
  "ServiceAccount",
  "ServicePrincipalNames",
  "SID",
  "SIDHistory",
  "TrustedForDelegation",
  "TrustedToAuthForDelegation",
  "UseDESKeyOnly",
  "UserPrincipalName"
);

# https://social.technet.microsoft.com/wiki/contents/articles/12089.active-directory-get-adorganizationalunit-default-and-extended-properties.aspx
$OrgUnitProps = @(
  "CanonicalName",
  "City",
  "CN",
  "Country",
  "Created",
  "Deleted",
  "Description",
  "DisplayName",
  "DistinguishedName",
  "LastKnownParent",
  "LinkedGroupPolicyObjects",
  "ManagedBy",
  "Modified",
  "Name",
  "ObjectCategory",
  "ObjectClass",
  "ObjectGUID",
  "PostalCode",
  "ProtectedFromAccidentalDeletion",
  "State",
  "StreetAddress"
);

Function Get-CommandResult {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [scriptblock]$Command
    )
    $output = @{};
    try {
        Write-Host "Running Command $($Command)"
        $output = $Command.invoke();
    }
    catch {
        #Write-Host "Command $Command failed. Exception: $($_.Exception.Message)"
    }
    return $output;
}

$Results = @{};
Write-Host "Collecting AD Information"
If ($AdminPassword -And $AdminUsername -And $ADServer) {
  $SecurePassword = $AdminPassword | ConvertTo-SecureString -AsPlainText -Force
  $Creds = New-Object System.Management.Automation.PSCredential($AdminUsername, $SecurePassword)
  $RootDSE = Get-CommandResult {Get-ADRootDSE -Server $ADServer -Credential $Creds};
  $configNCDN = $RootDSE.ConfigurationNamingContext;
  $siteContainerDN = ("CN=Sites," + $configNCDN);
  $Results = @{
    'Computers' = Get-CommandResult {Get-ADComputer -Server $ADServer -Credential $Creds -Filter * -Properties $ComputerProps | select-object $ComputerProps};
    'Domain' = Get-CommandResult {Get-ADDomain -Server $ADServer -Credential $Creds};
    'Forest' = Get-CommandResult {Get-ADForest -Server $ADServer -Credential $Creds};
    'Groups' = Get-CommandResult {Get-ADGroup -Server $ADServer -Credential $Creds -Filter * -Properties $GroupProps | select-object $GroupProps};
    'GroupPolicies' = Get-CommandResult {Get-GPO -Server $ADServer -All};
    'Users' = Get-CommandResult {Get-ADUser -Server $ADServer -Credential $Creds -Filter * -Properties $UserProps | select-object $UserProps};
    'Printers' = Get-CommandResult {Get-ADObject  -Server $ADServer -Credential $Creds -LDAPFilter "(objectCategory=printQueue)"};
    'OrganizationalUnits' = Get-CommandResult {Get-ADOrganizationalUnit -Server $ADServer -Credential $Creds -Filter * -Properties $OrgUnitProps | select-object $OrgUnitProps};
    'DomainControllers' = Get-CommandResult {Get-ADDomainController -Server $ADServer -Credential $Creds -Filter *};
    'RootDSE' = $RootDSE;
    'AccountPolicy' = Get-CommandResult {Get-ADDefaultDomainPasswordPolicy -Server $ADServer -Credential $Creds};
    'RawSites' = Get-CommandResult {Get-ADObject -Server $ADServer -Credential $Creds -SearchBase $siteContainerDN -filter { objectClass -eq "site" } -properties "siteObjectBL", name};
  }
} Else {
  $RootDSE = Get-CommandResult {Get-ADRootDSE};
  $configNCDN = $RootDSE.ConfigurationNamingContext;
  $siteContainerDN = ("CN=Sites," + $configNCDN);
  $Results = @{
    'Computers' = Get-CommandResult {Get-ADComputer -Filter * -Properties $ComputerProps | select-object $ComputerProps};
    'Domain' = Get-CommandResult {Get-ADDomain};
    'Forest' = Get-CommandResult {Get-ADForest};
    'Groups' = Get-CommandResult {Get-ADGroup -Filter * -Properties $GroupProps | select-object $GroupProps};
    'GroupPolicies' = Get-CommandResult {Get-GPO -All};
    'Users' = Get-CommandResult {Get-ADUser -Filter * -Properties $UserProps | select-object $UserProps};
    'Printers' = Get-CommandResult {Get-ADObject -LDAPFilter "(objectCategory=printQueue)"};
    'OrganizationalUnits' = Get-CommandResult {Get-ADOrganizationalUnit -Filter * -Properties $OrgUnitProps | select-object $OrgUnitProps};
    'DomainControllers' = Get-CommandResult {Get-ADDomainController -Filter *};
    'RootDSE' = $RootDSE;
    'AccountPolicy' = Get-CommandResult {Get-ADDefaultDomainPasswordPolicy};
    'RawSites' = Get-CommandResult {Get-ADObject -SearchBase $siteContainerDN -filter { objectClass -eq "site" } -properties "siteObjectBL", name};
  }
}
$Results.TimeOffset = &"C:\Windows\System32\w32tm.exe" /stripchart /computer:time.windows.com /dataonly /samples:5;
$Results.SiteSubnets = Get-CommandResult {Get-Subnets -Sites $Results.RawSites};

$DOMAINMODES = @{
  "0" = "Windows 2000 Domain"
  "1" = "Windows 2003 Domain"
  "2" = "Windows 2003 Interim Domain"
  "3" = "Windows 2008 Domain"
  "4" = "Windows 2008 R2 Domain"
  "5" = "Windows 2012 Domain"
  "6" = "Windows 2012 R2 Domain"
  "7" = "Windows 2016 Domain"
}

Write-Host "Generating Domain Information"
$Report = "Active Directory`r`n"
$Report += "----------------`r`n"
$Report += "`r`n"
$Report += "Domain: $($Results.Domain.Name)`r`n"
$Report += "Domain Mode: $($Results.Domain.DomainMode)`r`n"

$SiteSubnets = ""
$Results.SiteSubnets | foreach {
    $SiteSubnets += $_.SiteName
    $SiteSubnets += "("
    $Subnets = $_.Subnets
    for ($counter=0; $counter -lt $Subnets.Length; $counter++) {
        $SiteSubnets += $Subnets[$counter]
        If ($counter -gt 0 -and $counter -lt $Subnets.Length - 1) {
            $SiteSubnets += " | "
        }
    }
    $SiteSubnets += ")"
}
$Report += "Sites / Subnets: $($SiteSubnets)`r`n"
$Report += "Primary Domain Controllers: $($Results.Domain.PDCEmulator)`r`n"
$Report += "Infrastructure Masters: $($Results.Domain.InfrastructureMaster)`r`n"

Write-Host "Generating Users/Device Information"
$Report += "`r`n`r`nUsers/Devices`r`n"
$Report += "----------------`r`n"
$Report += "`r`n"

$UserStats = @{
    TotalUsers = 0
    ActiveUsers = 0
    LockedOutUsers = 0
    ExpiredUsers = 0
    DisabledUsers = 0
    DeletedUsers = 0
}

$CountPrivilegedUsers = 0
$PrivilegedUsersReport  = ""
$Results.Users | foreach {
  $today = Get-Date
  $expirationDate = Get-Date
  If ($_.AccountExpirationDate) {
    $expirationDate = [datetime]$_.AccountExpirationDate
  }

  If ($_.Deleted) { $UserStats.LockedOutUsers += 1 }
  ElseIf (!$_.Enabled) { $UserStats.DisabledUsers += 1 }
  ElseIf ($_.AccountExpirationDate -and $expirationDate -le $today) { $UserStats.ExpiredUsers += 1 }
  ElseIf ($_.Enabled -and $_.LockedOut) { $UserStats.LockedOutUsers += 1 }
  Else { $UserStats.ActiveUsers += 1 }
  $UserStats.TotalUsers += 1

  $IsPrivileged = $False
  If ($_.MemberOf) {
    $_.MemberOf | foreach {
      If ($_.ToLower() -like '*CN=*admin*') {
        $IsPrivileged = $True
      }
    }
  }

  If ($IsPrivileged) {
    $CountPrivilegedUsers += 1
    $PrivilegedUsersReport += $_.DistinguishedName + " | "
  }
}
$Report += "User Summary: $($UserStats.TotalUsers) Total | $($UserStats.ActiveUsers) Active | $($UserStats.LockedOutUsers) Locked Out | $($UserStats.ExpiredUsers) Expired | $($UserStats.DisabledUsers) Disabled | $($UserStats.DeletedUsers) Deleted`r`n"
$Report += "Total Privileged Users: $($CountPrivilegedUsers)`r`n"
$Report += "Privileged Users: $($PrivilegedUsersReport)`r`n"

Write-Host "Generating User Groups Information"
$Report += "Total Groups: $($Results.Groups.Length)`r`n"

$Results.Groups | foreach {
  $m = $_ | select -ExpandProperty Members
  
  If ($m.Length -gt 0) {
    $Report += "$($_.Name): "
    for ($counter=0; $counter -lt $m.Length; $counter++){
      If ($m[$counter] -match "CN=([\w\d-\s]+)") {
        $Results.Users | foreach {
            If ($m[$counter] -eq $_.DistinguishedName) {
                $Report += "$($_.DistinguishedName) | "
            }
        }
      }
    }

    $Report += "`r`n"
  }
}

$Report += "Total Computers: $($Results.Computers.Length)`r`n"

Write-Host "Generating Computer Information"
$ComputerTypes = @{}
$Results.Computers | foreach {
  $Type = "Template"
  If ($_.OperatingSystem) {
    If ($_.OperatingSystem.ToLower() -like '*server*') {
      $Type = "Server"
    } Else {
      $Type = "Workstation"
    }
  }

  If (!$ComputerTypes[$Type]) {
    $ComputerTypes[$Type] = 0
  }

  $ComputerTypes[$Type] = $ComputerTypes[$Type] + 1
}

$ComputerTypesReport = ""
for ($counter=0; $counter -lt $ComputerTypes.Keys.Length; $counter++){
  $Key = $ComputerTypes.Keys[$counter]
  $Value = $ComputerTypes[$Type]

  If ($Key) {
    $ComputerTypesReport += "$($Value) $($Key)"
    If ($counter -gt 0 -and $counter -lt $ComputerTypes.Keys.Length - 1) {
      $ComputerTypesReport += " | "
    }
  }
}
$Report += "Total Computer Types: $($ComputerTypesReport)`r`n"

$OrgUnitsReport = ""
for ($counter=0; $counter -lt $Results.OrganizationalUnits.Length; $counter++){
  $OrgUnitsReport += "$($Results.OrganizationalUnits[$counter].Name)"
  If ($counter -gt 0 -and $counter -lt $Results.OrganizationalUnits.Length - 1) {
    $OrgUnitsReport += " | "
  }
}
$Report += "Organizational Units: $($OrgUnitsReport)`r`n"

Write-Host "Generating Account Policy Information"
$Report += "`r`n`r`nACCOUNT POLICY`r`n"
$Report += "Policy - Minimum Password Length: $($Results.AccountPolicy.MinPasswordLength)`r`n"
$Report += "Policy - Password Complexity Requirement: $($Results.AccountPolicy.ComplexityEnabled)`r`n"
$Report += "Policy - Password History Count: $($Results.AccountPolicy.PasswordHistoryCount)`r`n"
$Report += "Policy - Max Password Age (days): $($Results.AccountPolicy.MaxPasswordAge)`r`n"
$Report += "Policy - Min Password Age (days): $($Results.AccountPolicy.MinPasswordAge)`r`n"
$Report += "Policy - Account Lockout Threshold: $($Results.AccountPolicy.LockoutThreshold)`r`n"
$Report += "Policy - Account Lockout Duration (hours:minutes:seconds): $($Results.AccountPolicy.LockoutDuration)`r`n"
$Report += "Policy - Account Lockout Observation Windows (hours:minutes:seconds): $($Results.AccountPolicy.LockoutObservationWindow)`r`n"

$now = $(Get-Date).tostring("MM-dd-yyyy")
Write-Host "Writing Report to Active-Directory-Report-$($now).txt"
$Report | Out-File -FilePath "Active-Directory-Report-$($now).txt" -Encoding UTF8

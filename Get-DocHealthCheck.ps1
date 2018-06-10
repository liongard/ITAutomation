# Get config types, count per each, last updated for each, avg last updated for each type, # of fields total, avg # of fields filled in
<#
.SYNOPSIS
  This script will produce a health check report on your Connectwise documentation, showing you the strengths and gaps in your current
  documentation.

.DESCRIPTION
  This script requires API access to your Connectwise instance. Instructions on how to allocate an API public/private key to use
  with Connectwise can be found at: 

.PARAMETER Url
  The url of your running connectwise instance

.PARAMETER CompanyID
  The company ID you use to login to Connectwise with.

.PARAMETER PublicKey
  The API public key.

.PARAMETER PrivateKey
  The API private key.
#>

[CmdletBinding()]
param (
  [parameter(Mandatory=$true, HelpMessage="The url of your running connectwise instance")]
  [string]
  $Url,

  [parameter(Mandatory=$true, HelpMessage="The company ID you use to login to Connectwise with.")]
  [string]
  $CompanyID,

  [parameter(Mandatory=$true, HelpMessage="The API public key.")]
  [string]
  $PublicKey,

  [parameter(Mandatory=$true, HelpMessage="The API private key.")]
  [string]
  $PrivateKey
)

# Call the login call to get the codebase
$Response = Invoke-WebRequest -Method "GET" -Uri "https://$($Url)/login/companyinfo/$($CompanyID)"
$info = $Response | ConvertFrom-Json

$creds = "$($CompanyID)+$($PublicKey):$($PrivateKey)"
$Bytes = [System.Text.Encoding]::ASCII.GetBytes($creds)
$EncodedText =[Convert]::ToBase64String($Bytes)

$headers = @{}
$headers.Add("Accept","application/json; application/vnd.connectwise.com+json; version=3.0.0")
$headers.Add("Authorization","Basic $($EncodedText)")
$Response = Invoke-WebRequest -Method "GET" -Uri "https://$($Url)/$($info.Codebase)apis/3.0/company/configurations" -Headers $headers 
$Configurations = $Response | ConvertFrom-Json

$CompanyName = ""

$ConfigHashMap = @{}
$ConfigCompanyHashMap = @{}
$Configurations | foreach {
  If (!$ConfigHashMap[$_.type.name]) {
    $ConfigHashMap[$_.type.name] = @{
      Count = 0
      Depth = 0
    }
  }
  $ConfigHashMap[$_.type.name].Count += 1

  $ConfigHashMap[$_.type.name].Depth = $_.questions.length
  $Quality = 0
  If (![string]::IsNullOrEmpty($_.locationId)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.serialNumber)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.modelNumber)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.tagNumber)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.purchaseDate)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.installationDate)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.warrantyExpirationDate)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.vendorNotes)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.macAddress)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.lastLoginName)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.ipAddress)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.manufacturer)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.vendor)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.backupSuccesses)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.backupIncomplete)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.backupFailed)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.backupRestores)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.lastBackupDate)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.backupServerName)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.backupProtectedDeviceList)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.backupYear)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.backupMonth)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.defaultGateway)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.osType)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.osInfo)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.cpuSpeed)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.ram)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.localHardDrives)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.activeFlag)) {
    $Quality += 1
  }
  If (![string]::IsNullOrEmpty($_.parentConfigurationId)) {
    $Quality += 10
  }
  $_.questions | foreach {
    If (![string]::IsNullOrEmpty($_.value)) {
      $Quality += 1
    } 
  }

  $ConfigHashMap[$_.type.name].Quality = 
    $ConfigHashMap[$_.type.name].Quality + $Quality

  If ($_.company.identifier -eq $CompanyID) {
    $CompanyName = $_.company.name
  }

  If (!$ConfigCompanyHashMap[$_.company.name]) {
    $ConfigCompanyHashMap[$_.company.name] = @{}
  }
  If (!$ConfigCompanyHashMap[$_.company.name][$_.type.name]) {
    $ConfigCompanyHashMap[$_.company.name][$_.type.name] = @{
      Count = 0
      Quality = 0
    }
  }
  $ConfigCompanyHashMap[$_.company.name][$_.type.name].Count += 1
  $ConfigCompanyHashMap[$_.company.name][$_.type.name].Quality = 
    $ConfigCompanyHashMap[$_.company.name][$_.type.name].Quality + $Quality

  $headers = @{}
  $headers.Add("Accept","application/json; application/vnd.connectwise.com+json; version=3.0.0")
  $headers.Add("Authorization","Basic $($EncodedText)")
  $Response = Invoke-WebRequest -Method "GET" -Uri "https://$($Url)/$($info.Codebase)apis/3.0/system/audittrail?type=Configuration&id=$($_.id)" -Headers $headers 
  
  # Last Change
  # Avg Days Between Last 25 changes
  $company = $_.company.name
  $type = $_.type.name
  $index = 0;
  $AuditTrail = $Response | ConvertFrom-Json
  $AuditTrail | foreach {
    If ($_.text.Contains("changed")) {
      $EndDate=(GET-DATE)
      $StartDate = [datetime]$_.enteredDate
      $ts = NEW-TIMESPAN –Start $StartDate –End $EndDate
      If ($index -eq 0) {
        $ConfigHashMap[$type].LastChangedOn = $ts.Days
        $ConfigCompanyHashMap[$company][$type].LastChangedOn = $ts.Days
      }

      If ($ts.Days -le 90) {
        $ConfigHashMap[$type].Changes += 1
        $ConfigCompanyHashMap[$company][$type].Changes += 1
      }

      $index += 1
    }
  }
}

$TableHtml = ''
$ConfigHashMap.Keys | % {
  $TableHtml += "<tr>"
  $TableHtml += "<td>$($_)</td>"
  $TableHtml += "<td style=""text-align: center;"">$($ConfigHashMap.Item($_).Count)</td>"
  $TableHtml += "<td style=""text-align: center;"">$($ConfigHashMap.Item($_).Depth)</td>"
  $TableHtml += "<td style=""text-align: center;"">$([math]::Floor($ConfigHashMap.Item($_).Quality / $ConfigHashMap.Item($_).Count))</td>"
  $TableHtml += "<td style=""text-align: center;"">$([math]::Floor($ConfigHashMap.Item($_).LastChangedOn / $ConfigHashMap.Item($_).Count))</td>"
  $TableHtml += "<td style=""text-align: center;"">$([math]::Floor($ConfigHashMap.Item($_).Changes / $ConfigHashMap.Item($_).Count))</td>"
  $TableHtml += "<td style=""text-align: center;"">$($ConfigHashMap.Item($_).Changes -eq 0)</td>"
  $TableHtml += "</tr>"
}

$TableCompanyHtml = ''
$ConfigCompanyHashMap.Keys | % {
  $company = $_
  $item = $ConfigCompanyHashMap.Item($company)
  $item.Keys | % {
    $TableCompanyHtml += "<tr>"
    $TableCompanyHtml += "<td>$($company)</td>"
    $TableCompanyHtml += "<td>$($_)</td>"
    $TableCompanyHtml += "<td style=""text-align: center;"">$($item.Item($_).Count)</td>"
    $TableCompanyHtml += "<td style=""text-align: center;"">$([math]::Floor($item.Item($_).Quality / $item.Item($_).Count))</td>"
    $TableCompanyHtml += "<td style=""text-align: center;"">$([math]::Floor($item.Item($_).LastChangedOn / $item.Item($_).Count))</td>"
    $TableCompanyHtml += "<td style=""text-align: center;"">$([math]::Floor($item.Item($_).Changes / $item.Item($_).Count))</td>"
    $TableCompanyHtml += "<td style=""text-align: center;"">$($item.Changes -eq 0)</td>"
    $TableCompanyHtml += "</tr>"
  }
}

$bodyStyle =
  "height: 100%;margin:0;font-size: 14px;line-height: 1.42857143;background-color: #f4f7fa;font-family: 'Ubuntu',sans-serif;color: #7f888f;-webkit-font-smoothing: antialiased;-moz-osx-font-smoothing: grayscale;"
$reportStyle =
  "background-color: #fff;border: 1px solid #e4eef0;margin-bottom: 50px;box-shadow: 0 1px 1px rgba(0,0,0,0.05);-webkit-box-shadow: 0 1px 1px rgba(0,0,0,0.05);"
$html = 
  "<html style=""height: 100%;"">" +
  "<head>" +
  "<title>Liongard Documentation Health Report</title>" +
  "</head>" +
  "<body style=$($bodyStyle)>" +
    "<div style=""padding: 15px;"">" +
      "<div style=$($reportStyle)>" +
        "<div style=""padding: 30px;padding-bottom: 10px;"">" +
          "<img style=""margin-right: 10px;font-family: 'Montserrat',sans-serif;float:left;border-radius: 4px;text-align: center;line-height: 50px;color: #fff;font-size: 30px;"" src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB8AAAAiCAYAAACnSgJKAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyRpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMC1jMDYxIDY0LjE0MDk0OSwgMjAxMC8xMi8wNy0xMDo1NzowMSAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENTNS4xIE1hY2ludG9zaCIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDozRjBGRkE0QjA1NkMxMUU4QTEyNDgzRTA0NkY1OTQ3RiIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDozRjBGRkE0QzA1NkMxMUU4QTEyNDgzRTA0NkY1OTQ3RiI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjNGMEZGQTQ5MDU2QzExRThBMTI0ODNFMDQ2RjU5NDdGIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOjNGMEZGQTRBMDU2QzExRThBMTI0ODNFMDQ2RjU5NDdGIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+OK3/NgAABqJJREFUeNqkV2ls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"" />" +
          "<div style=""float: left;"">" +
            "<h2 style=""font-size: 30px;margin: 0;font-family: 'Montserrat',sans-serif;"">$($CompanyName)</h2>" +
            "<div style=""color: #5c5e65;font-size: 14px;margin-left: 5px;"">Documentation Health Report</div>" +
          "</div>" +
        "</div>" +
        "<div style=""clear: both;margin-left: 40px;padding: 30px;padding-bottom: 70px;"">" +
          "<h3 style=""margin: 0;font-size: 24px;font-family: 'Montserrat',sans-serif;"">Health Score<span style=""font-weight: 600;color: #5090f7;padding-left: 15px;"">9 / 10</span></h3>" +
          "<hr/>" +
          "<div style=""font-size: 16px;font-weight: normal;color: #5d5d5d;"">Total Configurations: <u>($($Configurations.Length))</u></div>" +
          "<hr/>" +
          "<div style=""border-color: #e4eef0;margin-top: 30px;margin-bottom: 20px;background-color: #fff;border: 1px solid transparent;border-radius: 4px;-webkit-box-shadow: 0 1px 1px rgba(0,0,0,.05);box-shadow: 0 1px 1px rgba(0,0,0,.05);"">" +
            "<div style=""min-height: .01%;overflow-x: auto;margin-bottom: 0;border: 0;"">" +
              "<ul>" +
                "<li>Count: Total number of configurations found for this type, includes both active and inactive.</li>" +
                "<li>Depth: Number of properties beyond the default set that have been added to extend this configuration type.</li>" +
                "<li>Avg Quality of Data: Average number of fields, both default and custom, that are filled in for this configuration type. Higher is better but depends on the configuration type as to how many possible fields should be filled out.</li>" +
                "<li>Avg Days Since Last Update: Average number of days since an update to this configuration type has occurred.</li>" +
                "<li>Avg Number of Updates In Last 90 Days: Average number times in the last 90 days this configuration type has been updated.</li>" +
                "<li>Contains Stale Configurations: Whether any configuration of this type has not been updated at all in the past 90 days.</li>" +
              "</ul>" +
              "<h4 style=""margin-top: 10px;"">Configurations Breakdown</h4>" +
              "<table style=""width: 100%;max-width: 100%;background-color: transparent;border-spacing: 0;border-collapse: collapse;margin-bottom: 0;border-bottom-right-radius: 3px;border-bottom-left-radius: 3px;"">" +
                "<thead>" +
                  "<tr style=""background-color: #95a4b8;color: #fff;"">" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: left;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Configuration Type</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Count</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Depth</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Avg Quality of Data</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Avg Days Since Last Update</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Avg Number of Updates In Last 90 Days</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Contains Stale Configurations</th>" +
                  "</tr>" +
                "</thead>" +
                "<tbody>" +
                  "$($TableHtml)" +
                "</tbody>" +
              "</table>" +
              "<hr style=""margin-top: 15px;""/>" +
              "<h4>Per Company Configurations Breakdown</h4>" +
              "<table style=""width: 100%;max-width: 100%;background-color: transparent;border-spacing: 0;border-collapse: collapse;margin-bottom: 0;border-bottom-right-radius: 3px;border-bottom-left-radius: 3px;"">" +
                "<thead>" +
                  "<tr style=""background-color: #95a4b8;color: #fff;"">" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: left;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Company</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: left;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Configuration Type</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Count</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Avg Quality of Data</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Avg Days Since Last Update</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Avg Number of Updates In Last 90 Days</th>" +
                    "<th style=""padding-left: 12px;padding-right: 12px;vertical-align: bottom;padding: 8px;text-align: center;line-height: 1.42857143;border-top: 0;border-bottom: 0;"">Contains Stale Configurations</th>" +
                  "</tr>" +
                "</thead>" +
                "<tbody>" +
                  "$($TableCompanyHtml)" +
                "</tbody>" +
              "</table>" +
            "</div>" +
          "</div>" +
        "</div>" +
      "</div>" +
    "</div>" +
  "</body>" +
  "</html>"

$FDate = Get-Date -UFormat "%Y-%m-%d"
Out-File -FilePath "DocumentationHealthReport-$($FDate).html" -InputObject $html -Encoding ASCII

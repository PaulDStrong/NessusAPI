
Generates the encrypted keys. Can be run separately.
$ackey = Read-Host -AsSecureString
$ackeypt = $ackey | ConvertFrom-SecureString
$ackeypt | out-file 'C:\Temp\API Keys\AKey.txt'

# Generate your *.txt with the string you wanted encrypted
$seckey = Read-Host -AsSecureString
$seckeypt = $seckey | ConvertFrom-SecureString
$seckeypt | out-file 'C:\Temp\API Keys\SKey.txt'

$Stoploop = $false
[int]$Retrycount = "3"

#------------------Allow Selfsign Cert + workaround force TLS 1.2 connections---------------------
while (-not $Stoploop) {
Try {
#Ensure correct execution policy is set to run script. Administrative permission is required to Set-ExecutionPolicy.
#Set-ExecutionPolicy Bypass

$AllProtocols = [System.Net.SecurityProtocolType]'Tls12'

[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

add-type @"
	using System.Net;
	using System.Security.Cryptography.X509Certificates;
	public class TrustAllCertsPolicy : ICertificatePolicy {
		public bool CheckValidationResult(
			ServicePoint srvPoint, X509Certificate certificate,
			WebRequest request, int certificateProblem) {
				return true;
				}
	}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#------------------Input Variables-----------------------------------------------------------------
$Baseurl = "https://nessusURL:8834"
$ContentType = "application/json"
$POSTMethod = 'POST'
$GETMethod = 'GET'
$Header = (@{"X-ApiKeys"= "accessKey=$AccessKey;secretKey=$SecretKey"})


#----------------------Convert Encrypted APIs------------------------------------------------------

#  Recall and and decrypt the string for use in plaintext
$ackey = get-content 'C:\Temp\API Keys\AKey.txt' | ConvertTo-SecureString
$ABSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ackey)
$AccessKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ABSTR)

# Recall and and decrypt the string for use in plaintext
$seckey = get-content 'C:\Temp\API Keys\SKey.txt' | ConvertTo-SecureString
$SBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($seckey)
$SecretKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($SBSTR)

#------------------Create URI's--------------------------------------------------------------------

#Creates the URI variables to be used in script.

$ScansAPIurl = "/scans"
$ScansUri = $baseurl + $ScansAPIurl

#------------------Output completed scans----------------------------------------------------------

#Grabs all of the completed scans. 

(Invoke-RestMethod -Uri $ScansUri -Headers @{"X-ApiKeys"= "accessKey=$AccessKey;secretKey=$SecretKey"} -Method $GETMethod -ContentType "application/json").scans | 
				Where-Object {$_.status -eq "completed"} | 
				Select-Object @{Name = "Scan Name"; Expression = {$_.Name}},
@{Name = "Scan Status"; Expression = {$_.Status}},
@{Name = "Id"; Expression = {$_.id}} | 
    Format-Table -AutoSize
(Invoke-RestMethod -Uri $ScansUri -Headers @{"X-ApiKeys"= "accessKey=$AccessKey;secretKey=$SecretKey"} -Method $GETMethod -ContentType "application/json").scans | 
				Where-Object {$_.status -ne "completed"} | 
				Select-Object @{Name = "Scan Name"; Expression = {$_.Name}},
@{Name = "Scan Status"; Expression = {$_.Status}},
@{Name = "Id"; Expression = {$_.id}} | 
    Format-Table -AutoSize


#------------------Export Completed Scans (Y/N)----------------------------------------------------

#Chooses the export file type.
    $Format = 'csv'
    $ExportBody = convertto-json (New-Object PSObject -Property @{format = "$Format"})
    Write-Host "Checking Status...."
    
    
    
#------------------POST Export Requests------------------------------------------------------------

#Takes queued completed scans, groups them to export, then begins the download.
    $StatusArray = @()
    (Invoke-RestMethod -Uri $ScansUri -Headers @{"X-ApiKeys"= "accessKey=$AccessKey;secretKey=$SecretKey"} -Method $GETMethod -ContentType "application/json").scans |
        Where-Object {$_.status -eq "completed"} | select-object id, name |
        ForEach-Object {
        $Exportfile = @{
            Uri         = "$ScansUri" + "/" + $_.id + "/export"
            ContentType = $ContentType
            Headers     = $Header
            Method      = $POSTMethod
            Body        = $ExportBody
        }
        $file = (Invoke-RestMethod  @Exportfile ).file
        $ScanName = $_.name
        $StatusUri = "$ScansUri" + "/" + $_.id + "/export/" + "$file" + "/status"
        $DownloadUri = "$ScansUri" + "/" + $_.id + "/export/" + "$file" + "/download"
        $StatusArray += [pscustomobject]@{ScanName = $ScanName; StatusUri = $StatusUri; DownloadUri = $DownloadUri}
    }
    Start-Sleep -s 200

#------------------Check Status of Export requests-------------------------------------------------

    #Checks queue until prepared for download.  Array is created.
    Start-Sleep -s 125
    $Count = 0
    $StatusArray.StatusUri | ForEach-Object {
        (Invoke-RestMethod -Uri "$_" -ContentType $ContentType -Headers @{"X-ApiKeys"= "accessKey=$AccessKey;secretKey=$SecretKey"} -Method $GETMethod).status | 
            ForEach-Object {
            If ($_ -ne "ready") {
                $Count = $Count + 1
                Write-Host "Scan $Count not Ready. Scan is $_. Pausing for 30seconds..." -ForegroundColor Red
                Start-Sleep -s 30
            }
            else { 
                $Count = $Count + 1
                Write-Host "Scan $Count ready for export" -ForegroundColor Green
            }
        }
    }
    Write-Host ""
    Write-Host "Initiating Scan Export. Please wait for WebRequests to Complete..." -ForegroundColor Green
    Write-Host ""
    Start-Sleep -s 5
											  
#------------------Download the Reports------------------------------------------------------------

#Scans finally downloaded.  
    $ExportUri = $StatusArray.DownloadUri
    $outputs = $StatusArray.ScanName
    foreach ($i in 0..($ExportUri.Count - 1)) { 
        Invoke-WebRequest -Uri $ExportUri[$i] -ContentType $ContentType -Headers @{"X-ApiKeys"= "accessKey=$AccessKey;secretKey=$SecretKey"} -Method $GETMethod -OutFile "C:\Temp\Reports\$($outputs[$i]).$format"                 
    }
    Get-childitem c:\Temp\Reports\* -include *.nessus -Recurse | Rename-Item -NewName {$_.name -replace 'nessus', 'xml'}
    Write-Host ""
    Write-Host "Scans have been exported to ""C:\Temp\Reports\""" -ForegroundColor Green
    
    $Stoploop = $true
           
#------------------Reports Downloaded----------------------------------------------------------------------

}

catch {
if ($Retrycount -gt 1){
$Stoploop = $false
}
}
}



#Add Date column to report. Ideally this would be done in the reports.

$DMZR = import-csv -path "C:\Temp\Reports\DMZ Server .csv" | select -Skip 1
$Date = Get-Date -Format "yyyy-MM-dd"
ForEach ($item in $DMZR)
{ 
Add-Member -Input $item -MemberType NoteProperty -Name 'Date' -Value $Date -Force
}
$DMZR | Select-Object 'Plugin ID', 'CVE', 'CVSS', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Synopsis', 'Description', 'Solution', 'See Also', 'Plugin Output', 'Date' | Export-CSV -Path 'C:\Path' -NoTypeInformation 

#Add csvs to db table.  Modules can be found here: https://gallery.technet.microsoft.com/scriptcenter/4208a159-a52e-4b99-83d4-8048468d29dd

Import-Module C:\Windows\System32\WindowsPowerShell\v1.0\Modules\DataTable\Out-DataTable.ps1
Import-Module C:\Windows\System32\WindowsPowerShell\v1.0\Modules\DataTable\Write-DataTable.ps1


$DMZ = Import-CSV -Path  'C:\Temp\Reports\DMZ Server .csv' | Out-DataTable
Write-DataTable -ServerInstance "Server" -Database "Nessus" -TableName "DMZ" -Data $DMZ             

start-sleep -seconds 500 



Remove-Item -path 'C:\Temp\Reports\*'
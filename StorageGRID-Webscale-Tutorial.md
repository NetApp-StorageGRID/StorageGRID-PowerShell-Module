# StorageGRID Webscale PowerShell Cmdlet Tutorial

This tutorial will give an introduction to the StorageGRID Webscale PowerShell Cmdlets

## Discovering the available Cmdlets

Load the StorageGRID-Webscale Module

```powershell
Import-Module StorageGRID-Webscale
```

Show all available Cmdlets from the StorageGRID-Webscale Module

```powershell
Get-Command -Module StorageGRID-Webscale
```

Show the syntax of all Cmdlets from the StorageGRID-Webscale Module

```powershell
Get-Command -Module StorageGRID-Webscale -Syntax
```

To get detailed help including examples for a specific Cmdlet (e.g. for Connect-SGWServer) run

```powershell
Get-Help Connect-SGWServer -Detailed
```

## Connecting to a StorageGRID Management Server

For data retrieval a connection to the StorageGRID Management Server is required. The Connect-SGWServer Cmdlet expects the hostname or IP and the credentials for authentication

```powershell
$Server = "nms.mydomain.tld"
$Credential = Get-Credential
Connect-SGWServer -Name $Server -Credential $Credential
```

If the login fails, it is often due to an untrusted certificate of the StorageGRID Management Server. You can ignore the certificate check with the `-Insecure` option

```powershell
Connect-SGWServer -Name $Server -Credential $Credential -Insecure
```

By default the connection to the StorageGRID Webscale Server is established through HTTPS. If that doesn't work, HTTP will be tried. 

To force connections via HTTPS use the `-HTTPS` switch

```powershell
Connect-SGWServer -Name $Server -Credential $Credential -HTTPS
```

To force connections via HTTP use the `-HTTP` switch

```powershell
Connect-SGWServer -Name $Server -Credential $Credential -HTTP
```

## Create Tenant

To create a new S3 tenant use
```powershell
$Account = New-SGWAccount -Name Test -Capabilities s3
```
Then create S3 credentials with
```powershell
New-SGWAccountS3AccessKey -id $Account.id
```

## Simple workflow for exporting S3 account usage to CSV

In this simple workflow the S3 account usage data will be retrieved and exported as CSV to [$HOME\Downloads\TenantAccounting.csv]($HOME\Downloads\TenantAccounting.csv).

```powershell
$TenantAccounting = foreach ($Account in (Get-SGWAccounts | Where-Object { $_.capabilities -match "s3" })) {
    $Usage = $Account | Get-SGWAccountUsage
    $Output = New-Object -TypeName PSCustomObject -Property @{Name=$Account.name;ID=$Account.id;"Calculation Time"=$Usage.calculationTime;"Object Count"=$Usage.objectCount;"Data Bytes used"=$Usage.dataBytes}
    Write-Output $Output
}

$TenantAccounting | Export-Csv -Path $HOME\Downloads\TenantAccounting.csv -NoTypeInformation
```

The next workflow will retrieve the S3 Account usage per Bucket and export it as CSV to [$HOME\Downloads\BucketAccounting.csv]($HOME\Downloads\BucketAccounting.csv)

```powershell
$BucketAccounting = foreach ($Account in (Get-SGWAccounts | Where-Object { $_.capabilities -match "s3" })) {
    $Usage = $Account | Get-SGWAccountUsage
	foreach ($Bucket in $Usage.Buckets) {
		$Output = New-Object -TypeName PSCustomObject -Property @{Name=$Account.name;ID=$Account.id;"Calculation Time"=$Usage.calculationTime;Bucket=$Bucket.Name;"Object Count"=$Bucket.objectCount;"Data Bytes used"=$Bucket.dataBytes}
		Write-Output $Output
	}
}

$BucketAccounting | Export-Csv -Path $HOME\Downloads\TenantAccounting.csv -NoTypeInformation
```

## Report creation

StorageGRID allows to create reports for different metrics on grid, site and node level.

You can check the available metrics by using Command Completion. Just type the following command and hit the Tabulator key (->|)
```powershell
Get-SGWReport -Attribute 
```

The reports have a start and an end date. By default the attributes will be listed for the last hour. For attributes within the last 7 days StorageGRID will report the measure value in a specific interval. Attributes older than 7 days will be aggregated and StorageGRID will return average, minium and maximum value for each sample time. You can specify a time range using PowerShell DateTime objects.

Here are some examples:
```powershell
Get-SGWReport -Attribute 'S3 Ingest - Rate (XSIR) [MB/s]'
Get-SGWReport -Attribute 'S3 Retrieval - Rate (XSRR) [MB/s]' -StartTime (Get-Date).AddDays(-1)
Get-SGWReport -Attribute 'Used Storage Capacity (XUSC) [Bytes]' -StartTime (Get-Date).AddDays(-10) -EndTime (Get-Date).AddDays(-1)
```

By default the report is created for all nodes in the grid. To select a specific site or node, you need the OID of the site or node. The OIDs can be retrieved using the following Cmdlet
```powershell
$Topology = Get-SGWTopologyHealth
$Sites = $Topology.children
$Nodes = $Topology.children.children
```

To report only on the first site, use the following
```powershell
$Topology = Get-SGWTopologyHealth
$Sites = $Topology.children
$Site = $Sites[0]
Get-SGWReport -Attribute 'S3 Ingest - Rate (XSIR) [MB/s]' -OID $Site.oid
```

# S3 Operations



## Creating AWS Signatures

### Version 4

```powershell
$DebugPreference = "Continue"
# Example from http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
New-AwsSignatureV4 -AccessKey "test" -SecretAccessKey "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" -EndpointUrl "iam.amazonaws.com" -HTTPRequestMethod GET -Uri '/' -Query @{Action="ListUsers";Version="2010-05-08"} -ContentType "application/x-www-form-urlencoded; charset=utf-8" -DateTime "20150830T123600Z" -DateString "20150830" -Service "iam"
$DebugPreference = "SilentlyContinue"
```powershell

### Version 2

```powershell
$DebugPreference = "Continue"
# Examples from https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
$AccessKey = "AKIAIOSFODNN7EXAMPLE"
$SecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# Object GET
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "johnsmith.s3.amazonaws.com" -HTTPRequestMethod "GET" -DateTime "Tue, 27 Mar 2007 19:36:42 +0000" -Bucket "johnsmith" -Uri "/photos/puppy.jpg"
$Signature -eq "bWq2s1WEIj+Ydj0vQ697zp+IXMU="
# Object GET
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "johnsmith.s3.amazonaws.com" -HTTPRequestMethod "PUT" -DateTime "Tue, 27 Mar 2007 21:15:45 +0000" -Bucket "johnsmith" -Uri "/photos/puppy.jpg" -ContentType "image/jpeg"
$Signature -eq "MyyxeRY7whkBe+bq8fHCL/2kKUg="
# List
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "johnsmith.s3.amazonaws.com" -HTTPRequestMethod "GET" -DateTime "Tue, 27 Mar 2007 19:42:41 +0000" -Bucket "johnsmith"
$Signature -eq "htDYFYduRNen8P9ZfE/s9SuKy0U="
# Fetch
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "johnsmith.s3.amazonaws.com" -HTTPRequestMethod "GET" -DateTime "Tue, 27 Mar 2007 19:44:46 +0000" -Bucket "johnsmith" -QueryString "?acl"
$Signature -eq "c2WLPFtWHVgbEmeEG93a4cG37dM="
# Delete
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "s3.amazonaws.com" -HTTPRequestMethod "DELETE" -DateTime "Tue, 27 Mar 2007 21:20:26 +0000" -Bucket "johnsmith" -Uri "/johnsmith/photos/puppy.jpg"
$Signature -eq "$Signature -eq "
# Upload
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "static.johnsmith.net" -HTTPRequestMethod "PUT" -DateTime "Tue, 27 Mar 2007 21:06:08 +0000" -Bucket "static.johnsmith.net" -Uri "/db-backup.dat.gz" -ContentType "application/x-download" -ContentMD5 "4gJE4saaMU4BqNR0kLY+lw==" -Headers @{"x-amz-acl"="public-read";"content-type"="application/x-download";"Content-MD5"="4gJE4saaMU4BqNR0kLY+lw==";"X-Amz-Meta-ReviewedBy"="joe@johnsmith.net,jane@johnsmith.net";"X-Amz-Meta-FileChecksum"="0x02661779";"X-Amz-Meta-ChecksumAlgorithm"="crc32";"Content-Disposition"="attachment; filename=database.dat";"Content-Encoding"="gzip";"Content-Length"="5913339"}
$Signature -eq "ilyl83RwaSoYIEdixDQcA4OnAnc="
# List All My Buckets
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "s3.amazonaws.com" -HTTPRequestMethod "GET" -DateTime "Wed, 28 Mar 2007 01:29:59 +0000"
$Signature -eq "qGdzdERIC03wnaRNKh6OqZehG9s="
# Unicode Keys
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "s3.amazonaws.com" -HTTPRequestMethod "GET" -DateTime "Wed, 28 Mar 2007 01:49:49 +0000" -Uri "/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re"
$Signature -eq "qGdzdERIC03wnaRNKh6OqZehG9s="
$DebugPreference = "SilentlyContinue"
```
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
# StorageGRID Webscale PowerShell Cmdlet Tutorial

This tutorial will give an introduction to the StorageGRID Webscale and S3 PowerShell Cmdlets.

## Discovering the available Cmdlets

Since PowerShell 3 all available Modules are automatically loaded. To explicitly load the StorageGRID-Webscale Module use

```powershell
Import-Module -Name StorageGRID-Webscale
```

List all Cmdlets included in the StorageGRID-Webscale Module
	
```powershell
Get-Command -Module StorageGRID-Webscale
```

List all Cmdlets included in the S3 Client (this command only works with PowerShell 6 and later)

```powershell
Get-Command -Module S3-Client
```

Show the syntax of all Cmdlets from the StorageGRID-Webscale Module

```powershell
Get-Command -Module StorageGRID-Webscale -Syntax
```

Show the syntax of all Cmdlets from the StorageGRID-Webscale Module (this command only works with PowerShell 6 and later)

```powershell
Get-Command -Module S3-Client -Syntax
```

To get detailed help including examples for a specific Cmdlet (e.g. for Connect-SgwServer) run

```powershell
Get-Help Connect-SgwServer -Detailed
```

## Tutorial for Tenant Users

This section is dedicated to Tenant Users. If you are a Grid Administrator, check section [Tutorial for Grid Administrators]()

## Connect to a StorageGRID Management Server

For data retrieval a connection to the StorageGRID Management Server (also referred to as "Admin Node") is required. The `Connect-SgwServer` Cmdlet expects the hostname or IP (including port if different than 80 for HTTP or 443 for HTTPS) and the credentials for authentication

```powershell
$Name = "admin-node.example.org"
$Credential = Get-Credential
$Server = Connect-SgwServer -Name $Name -Credential $Credential
```

If the login fails, it is often due to an untrusted certificate of the StorageGRID Management Server. You can ignore the certificate check with the `-SkipCertificateCheck` option

```powershell
$Server = Connect-SgwServer -Name $Name -Credential $Credential -SkipCertificateCheck
```

By default the connection to the StorageGRID Webscale Server is established through HTTPS. If that doesn't work, HTTP will be tried.

The Cmdlets allow to connect either as Grid Administrator or as Tenant User. To connect to the StorageGRID Management Server as a tenant user specify the AccountId of the tenant. Ask a Grid Administrator for the AccountId of the tenant if you don't know it.

```powershell
Connect-SgwServer -Name $Name -Credential $Credential -AccountId $AccountId
```

## Tenant Management

To create a new S3 tenant use

```powershell
$Credential = Get-Credential -UserName root
$Account = New-SgwAccount -Name "MyTenant" -Capabilities s3,management -Password $Credential.GetNetworkCredential().Password
```

Check that Account was created either by listing all accounts

```powershell
Get-SgwAccounts
```

or by checking for the individual account

```powershell
$Account | Get-SgwAccount
```

Log in with the root user of the new tenant
```powershell
$Account | Connect-SgwServer -Name $Name -Credential $Credential
```

Then create S3 credentials and remember to store the access key and secret access key in a secure location
```powershell
New-SgwS3AccessKey
```

Check that S3 access keys have been created by listing all access key

```powershell
Get-SgwS3AccessKeys
```

or by checking for the individual account

```powershell
$AccessKey | Get-SgwS3AccessKey
```

The tenant can only be removed by a grid administrator. If you have stored the grid admin connection in the variable `$Server` as shown above, then you can use it here

```powershell
$Account | Remove-SgwAccount -Server $Server
```

Otherwise connect as grid administrator again and then run

```powershell
$Account | Remove-SgwAccount
```

## Export account usage to CSV

As a tenant user, the Account usage can be retrieved with

```powershell
Get-SgwAccountUsage
```

A grid administrator can use this simple workflow to retrieve the S3 account usage data and export it as CSV to [$HOME\Downloads\TenantAccounting.csv]($HOME\Downloads\TenantAccounting.csv).

```powershell
$TenantAccounting = foreach ($Account in (Get-SgwAccounts | Where-Object { $_.capabilities -match "s3" })) {
    $Usage = $Account | Get-SgwAccountUsage
    $Output = New-Object -TypeName PSCustomObject -Property @{Name=$Account.name;ID=$Account.id;"Calculation Time"=$Usage.calculationTime;"Object Count"=$Usage.objectCount;"Data Bytes used"=$Usage.dataBytes}
    Write-Output $Output
}

$TenantAccounting | Export-Csv -Path $HOME\Downloads\TenantAccounting.csv -NoTypeInformation
```

The next workflow will retrieve the S3 Account usage per Bucket and export it as CSV to [$HOME\Downloads\BucketAccounting.csv]($HOME\Downloads\BucketAccounting.csv)

```powershell
$BucketAccounting = foreach ($Account in (Get-SgwAccounts | Where-Object { $_.capabilities -match "s3" })) {
    $Usage = $Account | Get-SgwAccountUsage
	foreach ($Bucket in $Usage.Buckets) {
		$Output = New-Object -TypeName PSCustomObject -Property @{Name=$Account.name;ID=$Account.id;"Calculation Time"=$Usage.calculationTime;Bucket=$Bucket.Name;"Object Count"=$Bucket.objectCount;"Data Bytes used"=$Bucket.dataBytes}
		Write-Output $Output
	}
}

$BucketAccounting | Export-Csv -Path $HOME\Downloads\TenantAccounting.csv -NoTypeInformation
```

## Report creation

StorageGRID allows grid administrators to create reports for different metrics on grid, site and node level.

You can check the available metrics by using Command Completion. Just type the following command and hit the Tabulator key (->|)

```powershell
Get-SgwReport -Attribute 
```

The reports have a start and an end date. By default the attributes will be listed for the last hour. For attributes within the last 7 days StorageGRID will report the measure value in a specific interval. Attributes older than 7 days will be aggregated and StorageGRID will return average, minium and maximum value for each sample time. You can specify a time range using PowerShell DateTime objects.

Here are some examples:

```powershell
Get-SgwReport -Attribute 'S3 Ingest - Rate (XSIR) [MB/s]'
Get-SgwReport -Attribute 'S3 Retrieval - Rate (XSRR) [MB/s]' -StartTime (Get-Date).AddDays(-1)
Get-SgwReport -Attribute 'Used Storage Capacity (XUSC) [Bytes]' -StartTime (Get-Date).AddDays(-10) -EndTime (Get-Date).AddDays(-1)
```

By default the report is created for all nodes in the grid. To select a specific site specify the `-site` parameter

```powershell
Get-SgwReport -Attribute 'S3 Ingest - Rate (XSIR) [MB/s]' -Site $Site
```

To select a specific node specify the `-node` parameter

```powershell
Get-SgwReport -Attribute 'S3 Ingest - Rate (XSIR) [MB/s]' -Node $Node
```

## Retrieving Metrics

Retrieving individual metrics via REST API is possible since StorageGRID 11.0. To list the available metrics, run

```powershell
Get-SgwMetricNames
```

StorageGRID uses [Prometheus](https://prometheus.io/) to collect the metrics and [Prometheus Queries](https://prometheus.io/docs/querying/basics/) can be issued via e.g.

```powershell
Get-SgwMetricQuery -Query 'storagegrid_s3_operations_successful'  
```

# S3 Operations

The S3 Client included in the StorageGRID Webscale PowerShell Module allows to run S3 Operations against any S3 endpoint, but it includes some shortcuts for StorageGRID users to handle S3 credentials. If a grid administrator is connected, then the Cmdlets automatically create temporary Cmdlets for all tenants where an operation is performed. If a tenant user is connected, the temporary S3 credentials will be automatically created for the tenant user. All temporary credentials have an expiry time of 60 minutes by default.

When logged in as a tenant user, you must provide the `-endpointUrl` parameter for all S3 commands. For grid administrators the Cmdlets automatically query the configured domain endpoints and check if connections via S3 are possible. The endpoints are then stored in the S3EndpointUrl parameter of the server object (e.g. `$CurrentSgwServer.S3EndpointUrl`). It is alway possible to supply a different URL by specifying the `-EndpointUrl` parameter for all S3 commands.

For tenant users it is recommended to add the endpoint URL to the server object, so that the `-EndpointUrl` parameter is not required for every command. The following Commands expect that this has occured:

```powershell
$CurrentSgwServer.S3EndpointUrl = "https://s3.example.org:8082"   
```

## Access Keys

Automatic Access Key generation can be disabled when connecting to the StorageGRID server with

```powershell
Connect-SgwServer -Name $Name -Credential $Credential -SkipCertificateCheck -DisableAutomaticAccessKeyGeneration
```

The default expiry time of 60 minutes for temporary access keys can be changed when connecting to the StorageGRID Server with

```powershell
Connect-SgwServer -Name $Name -Credential $Credential -SkipCertificateCheck -TemporaryAccessKeyExpirationTime 300
```

All newly created credentials including temporary credentials will be stored per Account ID in the AccessKeyStore of the server object. Check it out with e.g.

```powershell
$CurrentSgwServer.AccessKeyStore
```

The grid administrator must be able to create S3 credentials for individual tenant accounts. This is only possible if the StorageGRID Webscale API Version 1 is enabled. For new installations of StorageGRID 10.4 or later, this is disabled by default. You can enable API Version 1 as grid administrator with

```powershell
Update-SgwConfigManagement -MinApiVersion 1
```

## Buckets

As a grid administrator, listing buckets will return all buckets for all tenants by creating S3 credentials for every tenant and then listing their buckets. For tenant users, only the buckets of the individual tenant will be listed.

```powershell
Get-S3Buckets
```

Grid Administrators can list all buckets of an individual tenant with

```powershell
Get-S3Buckets -AccountId $AccountId
```

or

```powershell
$Account = Get-SgwAccount -Tenant "MyTenant"
$Account | Get-S3Buckets
```

A new Bucket can be created with

```powershell
New-S3Bucket -Bucket "MyBucket"
```

A grid user needs to specify for which tenant the bucket should be created either by specifying the Account ID

```powershell
New-S3Bucket -Bucket "MyBucket" -AccountId $AccountId
```

or by retrieving an Account Object via e.g.

```powershell
$Account = Get-SgwAccount -Tenant "MyTenant"
$Account | New-S3Bucket -Bucket "MyBucket"
```

There are some StorageGRID specific S3 calls which are only supported by StorageGRID.

StorageGRID since 10.3 disables last access time updates if an object is retrieved as this causes a lot of updates on the Metadata databases and may cause slower response times if many objects are retrieved per second. 

The following Cmdlet checks if the last access time update is enabled for a bucket

```powershell
Get-S3BucketLastAccessTime -Bucket "MyBucket"
```

Updating the last access time for each object can be enabled per bucket with 

```powershell
Enable-S3BucketLastAccessTime -Bucket "MyBucket"  
```

It can be disabled with

```powershell
Disable-S3BucketLastAccessTime -Bucket "MyBucket"
```

StorageGRID supports different consistency settings for Buckets, which impact availability or integrity of the data. The consistency setting can be retrieved per Bucket with

```powershell
Get-S3BucketConsistency -Bucket "MyBucket"  
```

The consistency setting can be changed per Bucket with e.g.

```powershell
Update-S3BucketConsistency -Bucket "MyBucket" -Consistency available 
```

## Objects

Objects in a bucket can be listed with

```powershell
Get-S3Objects -Bucket "MyBucket"
```

Uploading objects can be done with

```powershell
Write-S3Object -Bucket "MyBucket" -InFile "$HOME\test"
```

Downloading objects can be done with

```powershell
Read-S3Object -Bucket "MyBucket" -Key "test" -OutFile "$HOME\test"
```

## Platform Services

### CloudMirror - Bucket Replication

Connected as a grid administrator, create a new tenant which is has S3 capabilities and is allowed to use platform services

```powershell
$Credential = Get-Credential -UserName "root"
$Account = New-SgwAccount -Name "platformservices" -Capabilities "s3","management" -Password $Credential.GetNetworkCredential().Password -AllowPlatformServices $true
```

Connect as tenant root user

```powershell
$Account | Connect-SgwServer -Name $Name -Credential $Credential
```

Create a bucket on StorageGRID to be mirrored to AWS. It is best practice to start bucket names with a random prefix

```powershell
$RandomPrefix = -join ((97..122) | Get-Random -Count 8 | % {[char]$_})
$SourceBucket = "$RandomPrefix-replication-source"
New-S3Bucket -Name $SourceBucket
Get-S3Buckets
```

To create a bucket on AWS the AWS credentials are required. If there is no AWS Profile yet, create a new profile configuration and add AWS Credentials retrieved from AWS IAM and a preferred region with
```powershell
Add-AwsConfig -Profile "AWS" -AccessKey "REPLACEME" -SecretAccessKey "REPLACEME" -Region "us-east-1"
```

Create the destination bucket on AWS using the AWS Profile

```powershell
$RandomPrefix = -join ((97..122) | Get-Random -Count 8 | % {[char]$_})
$DestinationBucket = "$RandomPrefix-replication-destination"
New-S3Bucket -Name $DestinationBucket -Profile "AWS"
Get-S3Buckets -Profile "AWS"
```

Configure the AWS destination bucket as Endpoint in StorageGRID

```powershell
Add-SgwS3Endpoint -DisplayName "AWS S3 endpoint" -Bucket $DestinationBucket -Profile "AWS"
```

Add a bucket replication rule which defines which source bucket (on StorageGRID) should be replicated to which destination bucket (on AWS)

```powershell
Add-SgwBucketReplicationRule -Bucket $SourceBucket -DestinationBucket $DestinationBucket -Id "AWS Replication of bucket $SourceBucket"
```

Write an object to the source bucket on StorageGRID

```powershell
$Key = "testobject"
$Content = "Hello World!"
Write-S3Object -Bucket $SourceBucket -Key $Key -Content $Content
```

Read the object from the source bucket

```powershell
Read-S3Object -Bucket $SourceBucket -Key $Key
```

Read the object from the destination bucket (you can add `-verbose` to verify that the REST call is indeed sent to AWS)

```powershell
Read-S3Object -Bucket $DestinationBucket -Key $Key -Profile "AWS"
```

## Creating AWS Signatures

To learn more about the AWS signing process, these Cmdlets can output helpful information in verbose and debug mode.

### Version 2

To see the detailed signing steps of the AWS V2 signing process, as shown in the examples of [Signing and Authenticating REST Requests](https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html) run

```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"
# Examples from 
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
$VerbosePreference = "SilentlyContinue"
$DebugPreference = "SilentlyContinue"
```

### Version 4

To see the detailed signing steps of the AWS V4 signing process, as shown in the examples of [Authenticating Requests: Using Query Parameters (AWS Signature Version 4)](http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html) run

```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"
New-AwsSignatureV4 -AccessKey "test" -SecretAccessKey "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" -EndpointUrl "iam.amazonaws.com" -HTTPRequestMethod GET -Uri '/' -Query @{Action="ListUsers";Version="2010-05-08"} -ContentType "application/x-www-form-urlencoded; charset=utf-8" -DateTime "20150830T123600Z" -DateString "20150830" -Service "iam"
$VerbosePreference = "SilentlyContinue"
$DebugPreference = "SilentlyContinue"
```
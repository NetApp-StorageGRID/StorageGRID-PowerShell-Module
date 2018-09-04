Import-Module StorageGRID-Webscale

$Credential = Get-Credential -UserName "florianf"

$SourceServer = Connect-SgwServer -Name $Name -Credential $Credential -Transient
$DestinationServer = Connect-SgwServer -Name $Name -Credential $Credential -Transient

$Credential = Get-Credential -UserName "root"

$Name = "webscalegmi.netapp.com"

$Name = "cbc-sg-admin-01.muccbc.hq.netapp.com"

$Name = "florianf-sgw-admin.muccbc.hq.netapp.com"

Connect-SgwServer -Name $Name -Credential $Credential -SkipCertificateCheck

$Account = Get-SgwAccounts | Where-Object { $_.Name -match "Florian Feldhaus" }

Update-SgwConfigManagement -MinApiVersion 1

$Account = New-SgwAccount -Name "nasbridge" -Capabilities "s3","management" -Quota 1TB -Password "netapp01"

$Account | New-SgwS3AccessKey

$Account = New-SgwAccount -Name "platform" -Capabilities "s3","management" -Quota 1TB -Password "netapp01"

$Account | Connect-SgwServer -Name $Name -Credential $Credential -SkipCertificateCheck

Add-AwsConfig -Profile "AWS" -AccessKey "REPLACEME" -SecretAccessKey "REPLACEME" -Region "us-east-1"

$Date = Get-Date -UFormat "%Y-%m-%d-%H%M"

$SourceBucket = "$Date-replication-source"

$DestinationBucket = "$Date-replication-destination"

Add-SgwS3Endpoint -DisplayName "AWS S3" -Bucket $DestinationBucket -Profile "AWS"

New-S3Bucket -Name $SourceBucket

Get-S3Buckets


New-S3Bucket -Profile "AWS" -Name $DestinationBucket

Get-S3Buckets -Profile "AWS"

Add-SgwBucketReplicationRule -Bucket $SourceBucket -DestinationBucket $DestinationBucket -Id "AWS Replication of bucket $SourceBucket"

Get-SgwBucketReplication -Name $SourceBucket

Write-S3Object -Bucket $SourceBucket -Key "test" -Content "test"

Read-S3Object -Bucket $SourceBucket -Key "test"

Read-S3Object -Bucket $DestinationBucket -Key "test" -Profile "AWS"
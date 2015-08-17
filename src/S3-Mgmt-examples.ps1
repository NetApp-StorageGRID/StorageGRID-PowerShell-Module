Import-Module ./S3-Mgmt.ps1

# Retrieve administrator credentials for StorageGRID NMS
$Credential = Get-Credential

# Connect to StorageGRID NMS
Connect-S3Mgmt -Name cbc-sg-adm1.muccbc.hq.netapp.com -Credential $credential -Insecure

# retrieve all S3 Accounts
Get-S3Accounts

# retrieve usage of each S3 Account
Get-S3Accounts | Get-S3AccountUsage

# create CSV Output S3 Account usage

$Accounting = foreach ($Account in Get-S3Accounts) {
    $Usage = Get-S3AccountUsage -id $Account.id
    $Output = New-Object -TypeName PSCustomObject -Property @{Name=$Account.name;ID=$Account.id;"Calculation Time"=$Usage.calculationTime;"Object Count"=$Usage.objectCount;"Data Bytes used"=$Usage.dataBytes}
    Write-Output $Output
} 

Export-Csv -Path C:\tmp\usage.csv -NoTypeInformation -InputObject $Accounting
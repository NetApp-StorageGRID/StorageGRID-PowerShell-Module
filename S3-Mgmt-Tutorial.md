# StorageGRID S3 Management PowerShell Cmdlet Tutorial

This tutorial will give an introduction to the StorageGRID S3 Management PowerShell Cmdlets

## Discovering the available Cmdlets

Load the S3-Mgmt Module

```powershell
Import-Module S3-Mgmt
```

Show all available Cmdlets from the S3-Mgmt Module

```powershell
Get-Command -Module S3-Mgmt
```

Show the syntax of all Cmdlets from the S3-Mgmt Module

```powershell
Get-Command -Module S3-Mgmt
```

To get detailed help including examples for a specific Cmdlet (e.g. for Connect-S3MgmtServer) run

```powershell
Get-Help Connect-S3MgmtServer -Detailed
```

## Connecting to a StorageGRID Management Server

For data retrieval a connection to the StorageGRID Management Server is required. The Connect-S3MgmtServer Cmdlet expects the hostname or IP and the credentials for authentication

```powershell
$ServerName = 'nms.stroagegrid.example.com'
$Credential = Get-Credential
Connect-S3MgmtServer -Name $ServerName -Credential $Credential
```

If the login fails, it is often due to an untrusted certificate of the StorageGRID Management Server. You can ignore the certificate check with the `-Insecure` option

```powershell
Connect-S3MgmtServer -Name $ServerName -Credential $Credential -Insecure
```

By default the connection to the S3Mgmt server is established through HTTPS. If that doesn't work, HTTP will be tried. 

To force connections via HTTPS use the `-HTTPS` switch

```powershell
Connect-S3MgmtServer -Name $ServerName -Credential $Credential -HTTPS
```

To force connections via HTTP use the `-HTTP` switch

```powershell
Connect-S3MgmtServer -Name $ServerName -Credential $Credential -HTTP
```

## Simple workflow for exporting S3 account usage to CSV

In this simple workflow the S3 account usage data will be retrieved and exported as CSV to (C:\tmp\usage.csv).

```powershell
$Accounting = foreach ($Account in Get-S3Accounts) {
    $Usage = Get-S3AccountUsage -id $Account.id
    $Output = New-Object -TypeName PSCustomObject -Property @{Name=$Account.name;ID=$Account.id;"Calculation Time"=$Usage.calculationTime;"Object Count"=$Usage.objectCount;"Data Bytes used"=$Usage.dataBytes}
    Write-Output $Output
} 

$Accounting | Export-Csv -Path C:\tmp\usage.csv -NoTypeInformation
```

StorageGRID Webscale PowerShell Module
======================================

The StorageGRID Webscale Module contains Cmdlets for managing a NetApp StorageGRID Webscale solution as well as basic S3 Cmdlets. While the S3 Cmdlets are working for any S3 object storage, they provide several enhancements to make S3 management easier for StorageGRID Webscale Administrators. For a [feature rich, performance optimized S3 Client in PowerShell use the official AWS Cmdlets](https://aws.amazon.com/de/powershell/).

Installation
------------

The recommended way to install the PowerShell Module is through the new Install-Module Cmdlet available in PowerShell 5. Consider installing [PowerShell 5](https://www.microsoft.com/en-us/download/details.aspx?id=50395) or [PowerShell 6](https://github.com/PowerShell/PowerShell#get-powershell) which supports Linux, Mac OS X and Windows. 

To install the Cmdlets for the current user only run

```powershell
Install-Module -Name StorageGRID-Webscale -Scope CurrentUser
```

To install the Cmdlets for all users, you need to run PowerShell as Administrator and then install them with

```powershell
Install-Module -Name StorageGRID-Webscale
```

The StorageGRID Webscale PowerShell Cmdlets require at least PowerShell 4.0 and .NET 4.5. 

If you can't install via `Install-Module` you can download the latest version of OnCommand-Insight.zip from the [GitHub Release page](https://github.com/ffeldhaus/StorageGRID-Webscale/releases/latest). Then extract StorageGRID-Webscale.zip to your preferred PowerShell Module location. For the current user to 
    
    $HOME\WindowsPowershell\Documents\WindowsPowerShell\Modules
    
For all users copy the folder to 

    C:\Windows\System32\WindowsPowerShell\v1.0\Modules
    
Update
------

If the Module was installed with `Install-Module`, it can be upgraded with

```powershell
Update-Module -Name StorageGRID-Webscale
```

If the Module was installed by downloading the ZIP file, then update the Module by replacing the StorageGRID-Webscale folder with the content of the new release ZIP file.

Usage
-----

Check if StorageGRID-Webscale Module can be found by PowerShell

```powershell
    Get-Module -ListAvailable StorageGRID-Webscale
```
    
Import PowerShell Module
	
```powershell
    Import-Module StorageGRID-Webscale
```

List all Cmdlets included in the StorageGRID-Webscale Module
	
```powershell
    Get-Command -Module StorageGRID-Webscale
```

List all Cmdlets included in the S3 Client

```powershell
    Get-Command -Module S3-Client  
```

Show help for Cmdlet to connect to StorageGRID Management Server
    
```powershell
    Get-Help Connect-SgwServer -Detailed
```

Connect to StorageGRID Management Server (use the `-Insecure` switch to skip checking the certificate of the server)

```powershell
    $Credential = Get-Credential
    $Server = "nms.mydomain.tld"
    Connect-SgwServer -Name $Server -Credential $Credential -Insecure
```

List all StorageGRID-Webscale Accounts

```powershell
    Get-SgwAccounts
```

Show StorageGRID-Webscale Account Usage

```powershell
    Get-SgwAccounts | Get-SgwAccountUsage
```
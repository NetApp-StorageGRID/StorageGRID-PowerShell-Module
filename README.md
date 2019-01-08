StorageGRID Webscale PowerShell Module
======================================

The StorageGRID Webscale Module contains Cmdlets for managing a NetApp StorageGRID Webscale solution as well as basic S3 Cmdlets. While the S3 Cmdlets are working for any S3 object storage, they provide several enhancements to make S3 management easier for StorageGRID Webscale Administrators. For a [feature rich, performance optimized S3 Client in PowerShell use the official AWS Cmdlets](https://aws.amazon.com/de/powershell/).

See the sections below for [Installation](#Installation) and [Update](#Update) Instructions see the sections below. For more information check out the [StorageGRID Webscale PowerShell Cmdlet Tutorial](StorageGRID-Webscale-Tutorial.md).

Installation
------------

The StorageGRID Webscale PowerShell Cmdlets require at least PowerShell 4.0 and .NET 4.5.

The recommended way to install the PowerShell Module is through the new Install-Module Cmdlet available since PowerShell 5. Consider installing [PowerShell 5](https://www.microsoft.com/en-us/download/details.aspx?id=50395) or [PowerShell 6](https://github.com/PowerShell/PowerShell#get-powershell). PowerShell 6 now supports Linux, Mac OS X and Windows.

By default PowerShell 5 and later have the official [Microsoft PowerShell Gallery](https://www.powershellgallery.com/) defined as installation source, but it is marked as `Untrusted`. To install the Cmdlets you need to trust this installation source using

```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
```

The StorageGRID Webscale Cmdlets are code signed. PowerShell (**currently only on Windows!**) can verify the code signature and only run signed code. To run the Cmdlets you need to ensure that your execution policy is set to either `AllSigned`, `RemoteSigned`, `Unrestricted`, `Bypass`. It is recommended to use `AllSigned`.

```powershell
Get-ExecutionPolicy
```

You can change the execution policy using the following command. It is recommended to change it only for the current user and use `AllSigned`:

```powershell
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope CurrentUser
```

To install the Cmdlets only for the current user run

```powershell
Install-Module -Name StorageGRID-Webscale -Scope CurrentUser
```

To install the Cmdlets for all users, you need to run PowerShell as Administrator and then install them with

```powershell
Install-Module -Name StorageGRID-Webscale
```

If you can't install via `Install-Module` you can download the latest version of StorageGRID-Webscale.zip from the [GitHub Release page](https://github.com/ffeldhaus/StorageGRID-Webscale/releases/latest). Then extract StorageGRID-Webscale.zip to your preferred PowerShell Module location. For the current user to

    $HOME\Documents\WindowsPowerShell\Modules

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

List all Cmdlets included in the S3 Client (this command only works with PowerShell 6 and later)

```powershell
    Get-Command -Module S3-Client
```

Show help for Cmdlet to connect to StorageGRID Management Server

```powershell
    Get-Help Connect-SgwServer -Detailed
```

Connect to StorageGRID Management Server (use the `-SkipCertificateCheck` switch to skip checking the certificate of the server)

```powershell
    $Credential = Get-Credential
    $Name = "admin-node.example.org"
    Connect-SgwServer -Name $Name -Credential $Credential -SkipCertificateCheck
```

List all StorageGRID-Webscale Accounts

```powershell
    Get-SgwAccounts
```

Show StorageGRID-Webscale Account Usage

```powershell
    Get-SgwAccounts | Get-SgwAccountUsage
```
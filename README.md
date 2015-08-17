S3-Mgmt
=======

StorageGRID S3 Management PowerShell Module

Installation
------------

Extract S3-Mgmt.zip either to your preferred PowerShell Module location (e.g. `$HOME\WindowsPowershell\Documents\WindowsPowerShell\Modules` or `C:\Windows\System32\WindowsPowerShell\v1.0\Modules`).

Usage
-----

Check if S3-Mgmt Module can be found by PowerShell

    Get-Module -ListAvailable S3-Mgmt
    
Import PowerShell Module
	
    Import-Module S3-Mgmt
    
List all Cmdlets included in the S3-Mgmt Module
	
    Get-Command -Module S3-Mgmt
	
Show help for Cmdlet to connect to StorageGRID Management Server
    
    Get-Help Connect-S3MgmtServer -Detailed
	
Connect to StorageGRID Management Server (use the `-Insecure` switch to skip checking the certificate of the server)
    
    $Credential = Get-Credential
    Connect-OciServer -Name myserver.mydomain.tld -Credential $Credential -Insecure
    
List all S3 Accounts

    Get-S3Accounts
	
Show Account Usage

    Get-S3Accounts | Get-S3AccountUsage

Trusting the Publisher of the S3-Mgmt Cmdlets
-------------------------------------------------------

This PowerShell Module is signed with a code signing certificate issued by the *NetApp Corp Issuing CA 1*. If the PowerShell execution policy requires powershell scripts to be signed (see [about_Execution_Policies](technet.microsoft.com/library/hh847748.aspx) for details), two steps are required to run this PowerShell Module

1. Trust the NetApp Root Certification Authority. This can be done with the following command executed in PowerShell `Start-Process powershell -Verb RunAs -ArgumentList '-nologo -command (New-Object System.Net.WebClient).DownloadFile(\"http://pki2.netapp.com/pki/NetApp%20Corp%20Root%20CA.crt\",\"$env:TEMP\netapp.crt\");certutil -addstore root $env:TEMP\netapp.crt;rm $env:TEMP\netapp.cr*;PAUSE'` or manually via the following steps:
  1. downloading the NetApp Root CA certificate from (http://pki1.netapp.com/pki/NetApp%20Corp%20Root%20CA.crt)
  2. double click on the downloaded file
  3. click on *Install Certificate...*
  4. click on *Next >*
  5. Select *Place all certificates in the following store*
  6. Click *Browse*
  7. Select *Trusted Root Certification Authorities*
  8. Click *OK*
  9. Click *Next >*
  10. Click Finish
  11. A *Security Warning* will be displayed. Click *Yes* to install the certificate. The *Thumbprint (sha1)* should be **9FFB6F1A 06BC0245 27368705 2E7309D3 6FF2CFD0**
  12. Click twice on *OK* to close the dialogs.
2. When importing the PowerShell module via `Import-Module S3-Mgmt` a dialog is displayed asking if the publisher *CN=florianf-Florian-Feldhaus, OU=Users, OU=EMEA, OU=Sites, DC=hq, DC=netapp, DC=com* should be trusted. Select *[A] Always run* to permanently trust this publisher.
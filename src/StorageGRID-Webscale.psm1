# workarounds for PowerShell issues
if ($PSVersionTable.PSVersion.Major -lt 6) {
    Add-Type @"
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

    # StorageGRID supports TLS 1.2 and PowerShell does not auto negotiate it, thus enforcing TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Using .NET JSON Serializer as JSON serialization included in Invoke-RestMethod has a length restriction for JSON content
    Add-Type -AssemblyName System.Web.Extensions
    $global:javaScriptSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $global:javaScriptSerializer.MaxJsonLength = [System.Int32]::MaxValue
    $global:javaScriptSerializer.RecursionLimit = 99

    # Functions necessary to parse JSON output from .NET serializer to PowerShell Objects
    function ParseItem($jsonItem) {
        if($jsonItem.PSObject.TypeNames -match "Array") {
            return ParseJsonArray($jsonItem)
        }
        elseif($jsonItem.PSObject.TypeNames -match "Dictionary") {
            return ParseJsonObject([HashTable]$jsonItem)
        }
        else {
            return $jsonItem
        }
    }
 
    function ParseJsonObject($jsonObj) {
        $result = New-Object -TypeName PSCustomObject
        foreach ($key in $jsonObj.Keys) {
            $item = $jsonObj[$key]
            if ($item) {
                $parsedItem = ParseItem $item
            } else {
                $parsedItem = $null
            }
            $result | Add-Member -MemberType NoteProperty -Name $key -Value $parsedItem
        }
        return $result
    }
 
    function ParseJsonArray($jsonArray) {
        $result = @()
        $jsonArray | ForEach-Object {
            $result += ,(ParseItem $_)
        }
        return $result
    }
 
    function ParseJsonString($json) {
        $config = $javaScriptSerializer.DeserializeObject($json)
        if ($config -is [Array]) {
            return ParseJsonArray($config)       
        }
        else {
            return ParseJsonObject($config)
        }
    }
}

### Helper Functions ###

function ParseExceptionBody($Response) {
    if ($Response) {
        $Reader = New-Object System.IO.StreamReader($Response.GetResponseStream())
        $Reader.BaseStream.Position = 0
        $Reader.DiscardBufferedData()
        $ResponseBody = $reader.ReadToEnd()
        if ($ResponseBody.StartsWith('{')) {
            $ResponseBody = $ResponseBody | ConvertFrom-Json | ConvertTo-Json
        }
        return $ResponseBody
    }
    else {
        return $Response
    }
}

### Cmdlets ###

<#
    .SYNOPSIS
    Connect to StorageGRID Webscale Management Server
    .DESCRIPTION
    Connect to StorageGRID Webscale Management Server
#>
function global:Connect-SGWServer {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=$True,
                   Position=0,
                   HelpMessage="The name of the StorageGRID Webscale Management Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.")][String]$Name,
        [parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage="A System.Management.Automation.PSCredential object containing the credentials needed to log into the StorageGRID Webscale Management Server.")][System.Management.Automation.PSCredential]$Credential,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="If the StorageGRID Webscale Management Server certificate cannot be verified, the connection will fail. Specify -Insecure to ignore the validity of the StorageGRID Webscale Management Server certificate.")][Switch]$Insecure,
        [parameter(Position=3,
                   Mandatory=$False,
                   HelpMessage="Specify -Transient to not set the global variable `$CurrentOciServer.")][Switch]$Transient
    )

    # check if untrusted SSL certificates should be ignored
    if ($Insecure) {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        else {
            if (!"Invoke-RestMethod:SkipCertificateCheck") {
                $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck",$true)
            }
            else {
                $PSDefaultParameterValues.'Invoke-RestMethod:SkipCertificateCheck'=$true
            }
        }
    }

    # TODO: Remove try/catch as soon as PowerShell 6 fixes OSVersion implementation
    try {
        if ([environment]::OSVersion.Platform -match "Win") {
            # check if proxy is used
            $ProxyRegistry = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $ProxySettings = Get-ItemProperty -Path $ProxyRegistry
            if ($ProxySettings.ProxyEnable) {
                Write-Warning "Proxy Server $($ProxySettings.ProxyServer) configured in Internet Explorer may be used to connect to the OCI server!"
            }
            if ($ProxySettings.AutoConfigURL) {
                Write-Warning "Proxy Server defined in automatic proxy configuration script $($ProxySettings.AutoConfigURL) configured in Internet Explorer may be used to connect to the OCI server!"
            }
        }
    }
    catch {}

    $Server = New-Object -TypeName PSCustomObject
    $Server | Add-Member -MemberType NoteProperty -Name Name -Value $Name
    $Server | Add-Member -MemberType NoteProperty -Name Credential -Value $Credential

    $Body = @"
{
    "username": "$($Credential.UserName)", 
    "password": "$($Credential.GetNetworkCredential().Password)"
}
"@
 
    # determine StorageGRID Version
    Try {
        $Response = Invoke-RestMethod -Method GET -Uri "https://$Name/api/versions" -TimeoutSec 10 -ContentType "application/json"
        $APIVersion = $Response.APIVersion -split "\." | select -first 1
    }
    Catch {
        $ResponseBody = ParseExceptionBody $_.Exception.Response
        if ($ResponseBody -match "apiVersion") {
            $APIVersion = ($ResponseBody | ConvertFrom-Json).APIVersion -split "\." | select -first 1
        }
    }

    if (!$APIVersion) {
        Write-Error "API Version could not be retrieved via https://$Name/api/versions"
        return
    }

    $BaseURI = "https://$Name/api/v$APIVersion"

    Try {
        $Response = Invoke-RestMethod -Method POST -Uri "$BaseURI/authorize" -TimeoutSec 10 -ContentType "application/json" -Body $body
        if ($Response.status -eq "success") {
            $Server | Add-Member -MemberType NoteProperty -Name APIVersion -Value $Response.apiVersion
            $Server | Add-Member -MemberType NoteProperty -Name Headers -Value @{"Authorization"="Bearer $($Response.data)"}
        }
    }
    Catch {
        $ResponseBody = ParseExceptionBody $_.Exception.Response
        if ($_.Exception.Message -match "Unauthorized") {                
            Write-Error "Authorization for $BaseURI/authorize with user $($Credential.UserName) failed"
            return
        }
        elseif ($ResponseBody -match "API version 1 is not supported") {
            $VersionTwo = $True
        }
        else {
            Write-Error "Login to $BaseURI/authorize failed via HTTPS protocol. Exception message: $($_.Exception.Message)`n $ResponseBody"
            return
        }
    }

    $Server | Add-Member -MemberType NoteProperty -Name BaseURI -Value $BaseURI

    if (!$Transient) {
        Set-Variable -Name CurrentSGWServer -Value $Server -Scope Global
    }

    return $Server
}

<#
    .SYNOPSIS
    Retrieve all StorageGRID Webscale Accounts
    .DESCRIPTION
    Retrieve all StorageGRID Webscale Accounts
#>
function Global:Get-SGWAccounts {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + '/grid/accounts'
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }
       
        Write-Output $Result.data
    }
}

<#
    .SYNOPSIS
    Retrieve a StorageGRID Webscale Account
    .DESCRIPTION
    Retrieve a StorageGRID Webscale Account
#>
function Global:Get-SGWAccount {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to get information for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Create a StorageGRID Webscale Account
    .DESCRIPTION
    Create a StorageGRID Webscale Account
#>
function Global:New-SGWAccount {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Name of the StorageGRID Webscale Account to be created.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$Name,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).")][String]$Capabilities,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }

        $Capabilities = '"' + ($Capabilities -split ',' -join '","') + '"'
    }
 
    Process {
        $Name = @($Name)
        foreach ($Name in $Name) {
            $Uri = $Server.BaseURI + "/grid/accounts"
            $Method = "POST"

            $Body = @"
{
    "name": "$Name",
    "capabilities": [ $Capabilities ]
}
"@

            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Delete a StorageGRID Webscale Account
    .DESCRIPTION
    Delete a StorageGRID Webscale Account
#>
function Global:Remove-SGWAccount {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to delete.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/accounts/$id"
        $Method = "DELETE"

        try {
            $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
            Write-Host "Successfully deleted account with ID $id"
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }
    }
}

<#
    .SYNOPSIS
    Update a StorageGRID Webscale Account
    .DESCRIPTION
    Update a StorageGRID Webscale Account
#>
function Global:Update-SGWAccount {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to update.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$Id,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).")][String[]]$Capabilities,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="New name of the StorageGRID Webscale Account.")][String]$Name,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }

        if ($Capabilities) {
            $Capabilities = '"' + ($Capabilities -split ',' -join '","') + '"'
        }
    }
 
    Process {
        $Id = @($Id)
        foreach ($Id in $Id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id"
            $Method = "PUT"

            if ($Name -and -not $Capabilities) {
                $Body = @"
{
    "name": "$Name"
}
"@
            }
            elseif ($Capabilities -and -not $Name) {
                $Body = @"
{
    "capabilities": [ $Capabilities ]
}
"@
            }
            else {
                $Body = @"
{
    "id": "$id",
    "name": "$Name",
    "capabilities": [ $Capabilities ]
}
"@
            }

            Write-Verbose $Body

            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Change Swift Admin Password for StorageGRID Webscale Account
    .DESCRIPTION
    Change Swift Admin Password for StorageGRID Webscale Account
#>
function Global:Update-SGWSwiftAdminPassword {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to update.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$Id,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Old Password.")][String]$OldPassword,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="New Password.")][String]$NewPassword,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Id = @($Id)
        foreach ($Id in $Id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/swift-admin-password"
            $Method = "POST"

            $Body = @"
{
  "password": "$NewPassword",
  "currentPassword": "$OldPassword"
}
"@
            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Retrieve StorageGRID Webscale Account Usage Report
    .DESCRIPTION
    Retrieve StorageGRID Webscale Account Usage Report
#>
function Global:Get-SGWAccountUsage {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to get usage information for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/usage"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Retrieve groups of a StorageGRID Webscale Account
    .DESCRIPTION
    Retrieve groups of a StorageGRID Webscale Account
#>
function Global:Get-SGWAccountGroups {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to get group information for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/groups"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Retrieve StorageGRID Webscale Account Usage Report
    .DESCRIPTION
    Retrieve StorageGRID Webscale Account Usage Report
#>
function Global:Get-SGWAccountUsage {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to get usage information for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/usage"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Retrieve StorageGRID Webscale Account S3 Access Keys
    .DESCRIPTION
    Retrieve StorageGRID Webscale Account S3 Access Keys
#>
function Global:Get-SGWAccountS3AccessKeys {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to get S3 Access Keys for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/s3-access-keys"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Retrieve a StorageGRID Webscale Account S3 Access Key
    .DESCRIPTION
    Retrieve a StorageGRID Webscale Account S3 Access Key
#>
function Global:Get-SGWAccountS3AccessKey {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="S3 Access Key ID to be deleted",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Id of the StorageGRID Webscale Account to delete S3 Access Key for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Id = @($Id)
        $AccountId = @($AccountId)

        foreach ($Index in 0..($Id.Count-1)) {
            $Uri = $Server.BaseURI + "/grid/accounts/$($AccountId[$Index])/s3-access-keys/$($Id[$Index])"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Create a new StorageGRID Webscale Account S3 Access Key
    .DESCRIPTION
    Create a new StorageGRID Webscale Account S3 Access Key
#>
function Global:New-SGWAccountS3AccessKey {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Id of the StorageGRID Webscale Account to create new S3 Access Key for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$Id,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="Expiration date of the S3 Access Key.")][DateTime]$Expires,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }

        if ($Expires) {
            $ExpirationDate = (Get-Date -Format s $Expires).ToString()
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/accounts/$id/s3-access-keys"
        $Method = "POST"

        if ($Expires) { 
            $Body = @"
{
    "expires": "$ExpirationDate"
}
"@
        }
        else {
            $Body = "{}"
        }

        try {
            $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }
       
        Write-Output $Result.data
    }
}

<#
    .SYNOPSIS
    Delete a StorageGRID Webscale Account S3 Access Key
    .DESCRIPTION
    Delete a StorageGRID Webscale Account S3 Access Key
#>
function Global:Remove-SGWAccountS3AccessKey {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="S3 Access Key ID to be deleted",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Id of the StorageGRID Webscale Account to delete S3 Access Key for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Id = @($Id)
        $AccountId = @($AccountId)
        foreach ($Index in 0..($Id.Count-1)) {
            $Uri = $Server.BaseURI + "/grid/accounts/$($AccountId[$Index])/s3-access-keys/$($Id[$Index])"
            $Method = "DELETE"

            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
                Write-Host "Successfully deleted S3 Access Key $AccessKey for ID $Id"
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
        }
    }
}

<#
    .SYNOPSIS
    Retrieve identity sources
    .DESCRIPTION
    Retrieve identity sources
#>
function Global:Get-SGWIdentitySources {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/identity-source"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }
       
        Write-Output $Result.data
    }
}

<#
    .SYNOPSIS
    Retrieve identity sources
    .DESCRIPTION
    Retrieve identity sources
#>
function Global:Update-SGWIdentitySources {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Identity Source ID",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$Id,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="Disable Identity Source ID")][Switch]$Disable,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="Identity Source Hostname")][String]$Hostname,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Identity Source Port")][Int]$Port,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Identity Source Username")][String]$Username,
        [parameter(
            Mandatory=$False,
            Position=5,
            HelpMessage="Identity Source Password")][String]$Password,
        [parameter(
            Mandatory=$False,
            Position=6,
            HelpMessage="Identity Source Base Group DN")][String]$BaseGroupDN,
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Identity Source Base User DN")][String]$BaseUserDN,
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Identity Source LDAP Service Type")][String]$LdapServiceType,
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Identity Source Type")][String]$Type,
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="Identity Source LDAP User ID Attribute")][String]$LDAPUserIDAttribute,
        [parameter(
            Mandatory=$False,
            Position=11,
            HelpMessage="Identity Source LDAP User UUID Attribute")][String]$LDAPUserUUIDAttribute,
        [parameter(
            Mandatory=$False,
            Position=12,
            HelpMessage="Identity Source LDAP Group ID Attribute")][String]$LDAPGroupIDAttribute,
        [parameter(
            Mandatory=$False,
            Position=13,
            HelpMessage="Identity Source Disable TLS")][Switch]$DisableTLS,
        [parameter(
            Mandatory=$False,
            Position=14,
            HelpMessage="Identity Source CA Certificate")][String]$CACertificate,
        [parameter(
            Mandatory=$False,
            Position=15,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Id = @($Id)
        
        foreach ($Id in $Id) {
            $Username = $Username -replace '([a-zA-Z0-9])\\([a-zA-Z0-9])','$1\\\\$2'

            $Body = @"
{
    "id": "$Id",
    "disable": $Disable,
    "hostname": "$Hostname",
    "port": $Port,
    "username": "$Username",
    "password": "$Password",
    "baseGroupDn": "$BaseGroupDN",
    "baseUserDn": "$BaseUserDN",
    "ldapServiceType": "$LDAPServiceType",
    "type": "$Type",
    "ldapUserIdAttribute": "$LDAPUserIDAttribute",
    "ldapUserUUIDAttribute": "$LDAPUserUUIDAttribute",
    "ldapGroupIdAttribute": "$LDAPGroupIDAttribute",
    "ldapGroupUUIDAttribute": "$LDAPGroupUUIDAttribute",
    "disableTls": $DisableTLS,
    "caCert": "$CACertificate\n"
}
"@
            $Uri = $Server.BaseURI + "/grid/identity-source"
            $Method = "PUT"

            try {
                $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Retrieve identity sources
    .DESCRIPTION
    Retrieve identity sources
#>
function Global:Sync-SGWIdentitySources {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/identity-source/synchronize"
        $Method = "POST"

        try {
            $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers -Body ""
            Write-Host "Successfully synchronized users and groups of identity sources"
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }
       
        Write-Output $Result.data
    }
}

<#
    .SYNOPSIS
    Get used capacity
    .DESCRIPTION
    Get used capacity
#>
function Global:Get-SGWCapacityUsed {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        Write-Warning "This Cmdlet uses an undocumented API call which may change in the future. Thus this Cmdlet is marked as experimental!"
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/private/attributes/XUSC"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }

        Write-Output $Result.data
    }
}

<#
    .SYNOPSIS
    Get total capacity
    .DESCRIPTION
    Get total capacity
#>
function Global:Get-SGWCapacityTotal {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        Write-Warning "This Cmdlet uses an undocumented API call which may change in the future. Thus this Cmdlet is marked as experimental!"
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/private/attributes/XISC"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }

        Write-Output $Result.data
    }
}

<#
    .SYNOPSIS
    .DESCRIPTION
#>
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        Write-Warning "This Cmdlet uses an undocumented API call which may change in the future. Thus this Cmdlet is marked as experimental!"
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/private/attributes/SRRT"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }

        Write-Output $Result.data
    }
}

<#
    .SYNOPSIS
    .DESCRIPTION
#>
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        Write-Warning "This Cmdlet uses an undocumented API call which may change in the future. Thus this Cmdlet is marked as experimental!"
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/private/attributes/SIRT"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }

        Write-Output $Result.data
    }
}
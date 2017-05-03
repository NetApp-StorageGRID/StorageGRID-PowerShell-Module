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

## accounts ##

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
    "password": "$($Credential.GetNetworkCredential().Password)",
    "cookie": true
}
"@
 
    $APIVersion = (Get-SGWVersions -Uri "https://$Name" | Sort | select -Last 1) -replace "\..*",""

    if (!$APIVersion) {
        Write-Error "API Version could not be retrieved via https://$Name/api/versions"
        return
    }

    $BaseURI = "https://$Name/api/v$APIVersion"

    Try {
        $Response = Invoke-RestMethod -Session Session -Method POST -Uri "$BaseURI/authorize" -TimeoutSec 10 -ContentType "application/json" -Body $body
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
        elseif ($_.Exception.Message -match "trust relationship") {
            Write-Error $_.Exception.Message
            Write-Information "Certificate of the server is not trusted. Use --insecure switch if you want to skip certificate verification."
        }
        else {
            Write-Error "Login to $BaseURI/authorize failed via HTTPS protocol. Exception message: $($_.Exception.Message)`n $ResponseBody"
            return
        }
    }

    $Server | Add-Member -MemberType NoteProperty -Name BaseURI -Value $BaseURI
    $Server | Add-Member -MemberType NoteProperty -Name Session -Value $Session

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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + '/grid/accounts'
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
            HelpMessage="Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).")][String[]]$Capabilities,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="Use account identity source (supported since StorageGRID 10.4).")][Boolean]$UseAccountIdentitySource=$true,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Quota for tenant in bytes.")][Long]$Quota,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Tenant root password.")][String]$Password,
        [parameter(
            Mandatory=$False,
            Position=5,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.APIVersion -ge 2 -and !$Password) {
            Throw "Password required"
        }
        if ($Server.APIVersion -lt 2 -and ($Quota -or $Password)) {
            Write-Warning "Quota and password will be ignored in API Version $($Server.APIVersion)"
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/accounts"
        $Method = "POST"

        $Body = @{}
        $Body.name = $Name[0]
        $Body.capabilities = $Capabilities

        if ($Server.APIVersion -ge 2) {
            $Body.password = $Password
            $Body.policy = @{"useAccountIdentitySource"=$UseAccountIdentitySource}
            if ($Quota) {
                $Body.policy.quotaObjectBytes = $Quota
            }
        }

        $Body = $Body | ConvertTo-Json

        Write-Verbose "Body: $Body"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/accounts/$id"
        $Method = "DELETE"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
            Mandatory=$False,
            Position=1,
            HelpMessage="Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).")][String[]]$Capabilities,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="New name of the StorageGRID Webscale Account.")][String]$Name,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Use account identity source (supported since StorageGRID 10.4).")][Boolean]$UseAccountIdentitySource=$true,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Quota for tenant in bytes.")][Long]$Quota,
        [parameter(
            Mandatory=$False,
            Position=5,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        
        if ($Server.APIVersion -lt 2 -and ($Quota -or $Password)) {
            Write-Warning "Quota and password will be ignored in API Version $($Server.APIVersion)"
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/accounts/$id"
        $Method = "PATCH"

        $Body = @{}
        if ($Name) {
            $Body.name = $Name
        }
        if ($Capabilities) {
            $Body.capabilities = $Capabilities
        }

        if ($Server.APIVersion -ge 2) {
            $Body.policy = @{"useAccountIdentitySource"=$UseAccountIdentitySource}
            if ($Quota) {
                $Body.policy.quotaObjectBytes = $Quota
            }
        }

        $Body = $Body | ConvertTo-Json

        Write-Verbose "Body: $Body"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
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
    Replace a StorageGRID Webscale Account
    .DESCRIPTION
    Replace a StorageGRID Webscale Account
#>
function Global:Replace-SGWAccount {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to update.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$Id,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).")][String[]]$Capabilities,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="New name of the StorageGRID Webscale Account.")][String]$Name,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Use account identity source (supported since StorageGRID 10.4).")][Boolean]$UseAccountIdentitySource=$true,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Quota for tenant in bytes.")][Long]$Quota,
        [parameter(
            Mandatory=$False,
            Position=5,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        
        if ($Server.APIVersion -lt 2 -and ($Quota -or $Password)) {
            Write-Warning "Quota and password will be ignored in API Version $($Server.APIVersion)"
        }
    }
 
    Process {
                $Body = @{}
        if ($Name) {
            $Body.name = $Name
        }
        if ($Capabilities) {
            $Body.capabilities = $Capabilities
        }

        if ($Server.APIVersion -ge 2) {
            $Body.policy = @{"useAccountIdentitySource"=$UseAccountIdentitySource}
            if ($Quota) {
                $Body.policy.quotaObjectBytes = $Quota
            }
        }

        $Body = $Body | ConvertTo-Json

        Write-Verbose "Body: $Body"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.APIVersion -gt 1) {
            Write-Error "This Cmdlet is only supported with API Version 1.0. Use the new Update-SGWPassword Cmdlet instead!"
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
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
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
    Changes the root user password for the Storage Tenant Account
    .DESCRIPTION
    Changes the root user password for the Storage Tenant Account
#>
function Global:Update-SGWPassword {
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.APIVersion -lt 2) {
            Write-Error "This Cmdlet is only supported with API Version 2.0 and later. Use the old Update-SGWSwiftAdminPassword Cmdlet instead!"
        }
    }
 
    Process {
        $Id = @($Id)
        foreach ($Id in $Id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/change-password"
            $Method = "POST"

            $Body = @"
{
  "password": "$NewPassword",
  "currentPassword": "$OldPassword"
}
"@
            try {
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/usage"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }
            Write-Output $Result.data
        }
    }
}

## alarms ##

<#
    .SYNOPSIS
    Retrieve all StorageGRID Webscale Alarms
    .DESCRIPTION
    Retrieve all StorageGRID Webscale Alarms
#>
function Global:Get-SGWAlarms {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="If set, acknowledged alarms are also returned")][Switch]$includeAcknowledged,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="Maximum number of results")][int]$limit
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + '/grid/alarms'
        $Method = "GET"

        $Separator = "?"
        if ($includeAcknowledged) {
            $Uri += "$($Separator)includeAcknowledged=true"
            $Separator = "&"
        }
        if ($limit) {
            $Uri += "$($Separator)limit=$limit"
        }

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
    Retrieve StorageGRID Health Status
    .DESCRIPTION
    Retrieve StorageGRID Health Status
#>
function Global:Get-SGWHealth {
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + '/grid/health'
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
    Retrieve StorageGRID Topology with Health Status
    .DESCRIPTION
    Retrieve StorageGRID Topology with Health Status
#>
function Global:Get-SGWTopologyHealth {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="Topology depth level to provide (default=node).")][String][ValidateSet("grid","site","node","component","subcomponent")]$Depth="node"
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/health/topology?depth=$depth"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }
       
        Write-Output $Result.data
    }
}

## config ##

<#
    .SYNOPSIS
    Retrieves global configuration and token information
    .DESCRIPTION
    Retrieves global configuration and token information
#>
function Global:Get-SGWConfig {
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/config"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
    Changes the global management API and UI configuration
    .DESCRIPTION
    Changes the global management API and UI configuration
#>
function Global:Update-SGWConfigManagement {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$True,
                   Position=0,
                   HelpMessage="Minimum API Version.")][Int][ValidateSet(1,2)]$MinApiVersion,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
           )


    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.APIVersion -lt 2) {
            Throw "Cmdlet not supported on server with API Version less than 2.0"
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/config/management"
        $Method = "PUT"

        $Body = @{minApiVersion=$MinApiVersion} | ConvertTo-Json
        Write-Verbose "Body: $Body"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body
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
    Retrieves the global management API and UI configuration
    .DESCRIPTION
    Retrieves the global management API and UI configuration
#>
function Global:Get-SGWConfigManagement {
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.APIVersion -lt 2) {
            Throw "Cmdlet not supported on server with API Version less than 2.0"
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/config/management"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
    Retrieve StorageGRID Product Version
    .DESCRIPTION
    Retrieve StorageGRID Product Version
#>
function Global:Get-SGWProductVersion {
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/config/product-version"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }
       
        Write-Output $Result.data.productVersion
    }
}

<#
    .SYNOPSIS
    Retrieves the major versions of the management API supported by the product release
    .DESCRIPTION
    Retrieves the major versions of the management API supported by the product release
#>
function Global:Get-SGWVersions {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="Uri of the StorageGRID Server")][String]$Uri
           )

    Begin {
        if ($Uri) {
            $Server = @{BaseURI="$Uri/api/v2";APIVersion=2}
        }
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/versions"
        $Method = "GET"

        Try {
            $Response = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
            $APIVersions = $Response.APIVersion
        }
        Catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            if ($ResponseBody -match "apiVersion") {
                $APIVersions = ($ResponseBody | ConvertFrom-Json).APIVersion
            }
            elseif ($_.Exception.Message -match "trust relationship") {
                Write-Error $_.Exception.Message
                Write-Information "Certificate of the server is not trusted. Use --insecure switch if you want to skip certificate verification."
            }
        }
       
        Write-Output $APIVersions
    }
}

## deactivated-features ##

<#
    .SYNOPSIS
    Retrieves the deactivated features configuration
    .DESCRIPTION
    Retrieves the deactivated features configuration
#>
function Global:Get-SGWDeactivatedFeatures {
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.APIVersion -lt 2) {
            Throw "This Cmdlet is only supported for API Version 2.0 and above"
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/deactivated-features"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
    Deactivates specific features. If no feature is selected, all features will be enabled again.
    .DESCRIPTION
    Deactivates specific features. If no feature is selected, all features will be enabled again.
#>
function Global:Update-SGWDeactivatedFeatures {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="Deactivate Alarm Acknowledgements.")][Boolean]$AlarmAcknowledgment,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="Deactivate Other Grid Configuration.")][Boolean]$OtherGridConfiguration,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="Deactivate Grid Topology Page Configuration.")][Boolean]$GridTopologyPageConfiguration,
        [parameter(Mandatory=$False,
                   Position=3,
                   HelpMessage="Deactivate Management of Tenant Accounts.")][Boolean]$TenantAccounts,
        [parameter(Mandatory=$False,
                   Position=4,
                   HelpMessage="Deactivate changing of tenant root passwords.")][Boolean]$ChangeTenantRootPassword,
        [parameter(Mandatory=$False,
                   Position=4,
                   HelpMessage="Deactivate maintenance.")][Boolean]$Maintenance,
        [parameter(Mandatory=$False,
                   Position=5,
                   HelpMessage="Deactivates activating features. This cannot be undone!")][Boolean]$ActivateFeatures,
        [parameter(Mandatory=$False,
                   Position=6,
                   HelpMessage="Deactivates managing of own S3 Credentials.")][Boolean]$ManageOwnS3Credentials,
        [parameter(Mandatory=$False,
                   Position=7,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
           )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.APIVersion -lt 2) {
            Throw "This Cmdlet is only supported for API Version 2.0 and above"
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/deactivated-features"
        $Method = "PUT"

        $Body = @{}
        if ($AlarmAcknowledgment -or $OtherGridConfiguration -or $GridTopologyPageConfiguration -or $TenantAccounts -or $ChangeTenantRootPassword -or $Maintenance -or $ActivateFeatures) {
            $Body.grid = @{}
        }
        if ($AlarmAcknowledgment) {
            $Body.grid.alarmAcknowledgment = $AlarmAcknowledgment
        }
        if ($OtherGridConfiguration) {
            $Body.grid.otherGridConfiguration = $OtherGridConfiguration
        }
        if ($GridTopologyPageConfiguration) {
            $Body.grid.gridTopologyPageConfiguration = $GridTopologyPageConfiguration
        }
        if ($TenantAccounts) {
            $Body.grid.tenantAccounts = $TenantAccounts
        }
        if ($ChangeTenantRootPassword) {
            $Body.grid.changeTenantRootPassword = $ChangeTenantRootPassword
        }
        if ($Maintenance) {
            $Body.grid.maintenance = $Maintenance
        }
        if ($ActivateFeatures) {
            $caption = "Please Confirm"    
            $message = "Are you sure you want to proceed with permanently deactivating the activation of features (this can't be undone!):"
            [int]$defaultChoice = 0
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Do the job."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Do not do the job."
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($no, $yes)
            $choiceRTN = $host.ui.PromptForChoice($caption,$message, $options,$defaultChoice)
            if ($choiceRTN -eq 1) {
                $Body.grid.activateFeatures = $ActivateFeatures
            }
            else {
                Write-Host "Deactivating of permanent feature activation aborted."
                return
            }
        }
        if ($ManageOwnS3Credentials) {
            $Body.tenant = @{manageOwnS3Credentials=$ManageOwnS3Credentials}
        }
        $Body = $Body | ConvertTo-Json

        Write-Verbose "Body: $Body"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType application/json
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }
       
        Write-Output $Result.data
    }
}


## dns-servers ##

<#
    .SYNOPSIS
    Retrieve StorageGRID DNS Servers
    .DESCRIPTION
    Retrieve StorageGRID DNS Servers
#>
function Global:Get-SGWDNSServers {
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/dns-servers"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
    Retrieve StorageGRID DNS Servers
    .DESCRIPTION
    Retrieve StorageGRID DNS Servers
#>
function Global:Replace-SGWDNSServers {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage="List of IP addresses of the external DNS servers.")][String[]]$DNSServers
           )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/dns-servers"
        $Method = "PUT"

        $Body = '["' + ($DNSServers -join '","') + '"]'

        Write-Verbose $Body

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/groups"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/usage"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/s3-access-keys"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Id = @($Id)
        $AccountId = @($AccountId)

        foreach ($Index in 0..($Id.Count-1)) {
            $Uri = $Server.BaseURI + "/grid/accounts/$($AccountId[$Index])/s3-access-keys/$($Id[$Index])"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
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
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Id = @($Id)
        $AccountId = @($AccountId)
        foreach ($Index in 0..($Id.Count-1)) {
            $Uri = $Server.BaseURI + "/grid/accounts/$($AccountId[$Index])/s3-access-keys/$($Id[$Index])"
            $Method = "DELETE"

            try {
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/identity-source"
        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
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
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body
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
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/identity-source/synchronize"
        $Method = "POST"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body ""
            Write-Host "Successfully synchronized users and groups of identity sources"
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }
       
        Write-Output $Result.data
    }
}

### reporting ###

<#
    .SYNOPSIS
    Get StorageGRID Report
    .DESCRIPTION
    Get StorageGRID Report
#>
function Global:Get-SGWReport {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Attribut to report")][String][ValidateSet("Archive Nodes Installed (XANI)","Archive Nodes Readable (XANR)","Archive Nodes Writable (XANW)","Awaiting - All (XQUZ)","Awaiting - Client (XCQZ)","Awaiting - Evaluation Rate (XEVT)","CDMI - Ingested Bytes (XCRX) [Bytes]","CDMI - Retrieved Bytes (XCTX) [Bytes]","CDMI Ingest - Rate (XCIR) [MB/s]","CDMI Operations - Failed (XCFA)","CDMI Operations - Rate (XCRA) [Objects/s]","CDMI Operations - Successful (XCSU)","CDMI Retrieval - Rate (XCRR) [MB/s]","Current ILM Activity (IQSZ)","Installed Storage Capacity (XISC) [Bytes]","Percentage Storage Capacity Used (PSCU)","Percentage Usable Storage Capacity (PSCA)","S3 - Ingested Bytes (XSRX) [Bytes]","S3 - Retrieved Bytes (XSTX) [Bytes]","S3 Ingest - Rate (XSIR) [MB/s]","S3 Operations - Failed (XSFA)","S3 Operations - Rate (XSRA) [Objects/s]","S3 Operations - Successful (XSSU)","S3 Operations - Unauthorized (XSUA)","S3 Retrieval - Rate (XSRR) [MB/s]","Scan Period - Estimated (XSCM) [us]","Scan Rate (XSCT) [Objects/s]","Storage Nodes Installed (XSNI)","Storage Nodes Readable (XSNR)","Storage Nodes Writable (XSNW)","Swift - Ingested Bytes (XWRX) [Bytes]","Swift - Retrieved Bytes (XWTX) [Bytes]","Swift Ingest - Rate (XWIR) [MB/s]","Swift Operations - Failed (XWFA)","Swift Operations - Rate (XWRA) [Objects/s]","Swift Operations - Successful (XWSU)","Swift Operations - Unauthorized (XWUA)","Swift Retrieval - Rate (XWRR) [MB/s]","Total EC Objects (XECT)","Total EC Reads - Failed (XERF)","Total EC Reads - Successful (XERC)","Total EC Writes - Failed (XEWF)","Total EC Writes - Successful (XEWC)","Total Objects Archived (XANO)","Total Objects Deleted (XANP)","Total Size of Archived Objects (XSAO)","Total Size of Deleted Objects (XSAP)","Usable Storage Capacity (XASC) [Bytes]","Used Storage Capacity (XUSC) [Bytes]","Used Storage Capacity for Data (XUSD) [Bytes]","Used Storage Capacity for Metadata (XUDC) [Bytes]")]$Attribute,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="Topology OID to create report for")][String]$OID,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="Start Time")][DateTime]$StartTime=(Get-Date).AddHours(-1),
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="End Time")][DateTime]$EndTime=(Get-Date)
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
    }
 
    Process {
        $StartTimeString = $StartTime.ToUniversalTime() | Get-Date -UFormat "%Y%m%d%H%M%S"
        $EndTimeString = $EndTime.ToUniversalTime() | Get-Date -UFormat "%Y%m%d%H%M%S"

        $AttributeCode = $Attribute -replace ".*\((.+)\).*",'$1'

        if (!$OID) {
            $OID = (Get-SGWTopologyHealth).oid
        }

        $Method = "GET"
        $Uri = "https://florianf-sgw-admin.muccbc.hq.netapp.com/NMS/render/JSP/DoXML.jsp?requestType=RPTX&mode=PAGE&start=$StartTimeString&end=$EndTimeString&attr=$AttributeCode&attrIndex=1&oid=$OID&type=text"

        try {
            $Result = Invoke-RestMethod -Method $Method -WebSession $Server.Session -Headers $Server.Headers -Uri $Uri
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }

        $Body = ($Result -split "`n" | ? { $_ -match "<body" })
        Write-Verbose "Body: $Body"

        if ($Result -match "Aggregate Time") {
            $Report = $Body -replace "<body.*Aggregate Time.*Type<br>","" -split "<br>" -replace "([^,]+),[^,]+,([^ ]+) ([^,]*),([^ ]+) ([^,]*),([^ ]+) ([^,]*),.+",'$1;$2;$4;$6' | ? { $_ }
            foreach ($Line in $Report) {
                $Time,$Average,$Minimum,$Maximum = $Line -split ';'
                $Average=$Average -replace ",","" -replace " ",""
                $Minimum=$Minimum -replace ",","" -replace " ",""
                $Maximum=$Maximum -replace ",","" -replace " ",""
                [PSCustomObject]@{"Time Received"= [DateTime]$time;"Average $Attribute"=$Average;"Minimum $Attribute"=$Minimum;"Maximum $Attribute"=$Maximum}
            }
        }
        elseif ($Result -match "Time Received") {
            $Report = $Body -replace "<body.*Time Received.*Type<br>","" -split "<br>" -replace "([^,]+),[^,]+,[^,]+,[^,]+,([^ ]+) ([^,]*),.+",'$1;$2' | ? { $_ }
            foreach ($Line in $Report) {
                $Time,$Value = $Line -split ';'
                $Value=$Value -replace ",","" -replace " ",""
                [PSCustomObject]@{"Time Received"= [DateTime]$time;$Attribute=$value}
            }
        }
        else {
            Write-Error "Cannot parse report output"
        }
    }
}
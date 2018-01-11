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

# helper function to convert datetime to unix timestamp
function ConvertTo-UnixTimestamp {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$True,
                    Position=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True,
                    HelpMessage="Date to be converted.")][DateTime[]]$Date
    )

    BEGIN {
        $epoch = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0
    }

    PROCESS {
        $Date = @($Date)

        foreach ($Date in $Date) {
                $milliSeconds = [math]::truncate($Date.ToUniversalTime().Subtract($epoch).TotalMilliSeconds)
                Write-Output $milliSeconds
        }
    }
}

# helper function to convert unix timestamp to datetime
function ConvertFrom-UnixTimestamp {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$True,
                    Position=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True,
                    HelpMessage="Timestamp to be converted.")][String]$Timestamp,
        [parameter(Mandatory=$True,
                    Position=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True,
                    HelpMessage="Unit of timestamp.")][ValidateSet("Seconds","Milliseconds")][String]$Unit="Milliseconds",
        [parameter(Mandatory=$False,
                    Position=1,
                    HelpMessage="Optional Timezone to be used as basis for Timestamp. Default is system Timezone.")][System.TimeZoneInfo]$Timezone=[System.TimeZoneInfo]::Local
    )

    PROCESS {
        $Timestamp = @($Timestamp)
        foreach ($Timestamp in $Timestamp) {
            if ($Unit -eq "Seconds") {
                $Date = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]'1/1/1970').AddSeconds($Timestamp),$Timezone)
            }
            else {
                $Date = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]'1/1/1970').AddMilliseconds($Timestamp),$Timezone)
            }
            Write-Output $Date
        }
    }
}

### Cmdlets ###

## accounts ##

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
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="Maximum number of results.")][Int]$Limit=0,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="Pagination offset (value is Account's id).")][String]$Marker,
        [parameter(Mandatory=$False,
                   Position=3,
                   HelpMessage="if set, the marker element is also returned.")][Switch]$IncludeMarker,
        [parameter(Mandatory=$False,
                   Position=4,
                   HelpMessage="pagination order (desc requires marker).")][ValidateSet("asc","desc")][String]$Order="asc"
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {

        $Uri = $Server.BaseURI + '/grid/accounts'
        $Method = "GET"

        if ($Limit -eq 0) {
            $Query = "?limit=25"
        }
        else {
            $Query = "?limit=$Limit"
        }
        if ($Marker) { $Query += "&marker=$Marker" }
        if ($IncludeMarker) { $Query += "&includeMarker=true" }
        if ($Order) { $Query += "&order=$Order" }

        $Uri += $Query
        
        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $($responseBody.message)"
            return
        }

        $Result.data | Add-Member -MemberType AliasProperty -Name accountId -Value id

        Write-Output $Result.data

        if ($Limit -eq 0 -and $Result.data.count -eq 25) {
            Get-SGWAccounts -Server $Server -Limit $Limit -Marker ($Result.data | select -last 1 -ExpandProperty id) -IncludeMarker:$IncludeMarker -Order $Order
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
            HelpMessage="Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).")][ValidateSet("swift","s3","management")][String[]]$Capabilities,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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

        $Body = ConvertTo-Json -InputObject $Body

        Write-Verbose "Body: $Body"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }

        $Result.data | Add-Member -MemberType AliasProperty -Name accountId -Value id
       
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
            ValueFromPipelineByPropertyName=$True)][String]$id,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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
    [CmdletBinding(DefaultParameterSetName="id")]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            ParameterSetName="id",
            HelpMessage="ID of a StorageGRID Webscale Account to get information for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$id,
        [parameter(
            Mandatory=$False,
            Position=0,
            ParameterSetName="name",
            HelpMessage="Name of a StorageGRID Webscale Account to get information for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$Name,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        if ($Name) {
            # this is a convenience method for retrieving an account by name
            $Account = Get-SGWAccounts | ? { $_.Name -eq $Name }
            Write-Output $Account
        }
        else {
            $Uri = $Server.BaseURI + "/grid/accounts/$id"
            $Method = "GET"

            try {
                $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $ResponseBody = ParseExceptionBody $_.Exception.Response
                Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            }

            $Result.data | Add-Member -MemberType AliasProperty -Name accountId -Value id
       
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
            ValueFromPipelineByPropertyName=$True)][String]$Id,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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

        $Body = ConvertTo-Json -InputObject $Body

        Write-Verbose "Body: $Body"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }

        $Result.data | Add-Member -MemberType AliasProperty -Name accountId -Value id
       
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
            ValueFromPipelineByPropertyName=$True)][String]$Id,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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

        $Body = ConvertTo-Json -InputObject $Body

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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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
            Mandatory=$False,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to get usage information for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$id,
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
        if (!$Id) {
            if (!$Server.AccountId) {
                throw "No ID specified and not connected as tenant user. Either specify an ID or use Connect-SgwServer with the parameter accountId."
            }
            else {
                $Uri = $Server.BaseURI + "/org/usage"
            }
        }
        else {
            $Uri = $Server.BaseURI + "/grid/accounts/$id/usage"
        }

        $Method = "GET"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            return
        }
        Write-Output $Result.data
    }
}

## auth ##

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
                   HelpMessage="Specify -Transient to not set the global variable `$CurrentOciServer.")][Switch]$Transient,
        [parameter(Position=4,
                   Mandatory=$False,
                   HelpMessage="Account ID of tenant to connect to.")][String]$AccountId
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
    else {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $PSDefaultParameterValues.Remove("Invoke-RestMethod:SkipCertificateCheck")
        }
    }

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

    $Server = New-Object -TypeName PSCustomObject
    $Server | Add-Member -MemberType NoteProperty -Name Name -Value $Name
    $Server | Add-Member -MemberType NoteProperty -Name Credential -Value $Credential

    $Body = @{}
    $Body.username = $Credential.UserName
    $Body.password = $Credential.GetNetworkCredential().Password
    $Body.cookie = $True
    $Body.csrfToken = $True

    if ($AccountId) {
        $Body.accountId = $AccountId
        $Server | Add-Member -MemberType NoteProperty -Name AccountId -Value $AccountId
    }

    $Body = ConvertTo-Json -InputObject $Body

    Write-Verbose "Body:`n$Body"
 
    $APIVersion = (Get-SGWVersion -Uri "https://$Name" | Sort-Object | select -Last 1) -replace "\..*",""

    if (!$APIVersion) {
        Write-Error "API Version could not be retrieved via https://$Name/api/versions"
        return
    }

    $BaseURI = "https://$Name/api/v$APIVersion"
    $Server | Add-Member -MemberType NoteProperty -Name BaseURI -Value $BaseURI

    Try {
        $Response = Invoke-RestMethod -Session Session -Method POST -Uri "$BaseURI/authorize" -TimeoutSec 10 -ContentType "application/json" -Body $Body
        if ($Response.status -eq "success") {
            $Server | Add-Member -MemberType NoteProperty -Name APIVersion -Value $Response.apiVersion
            $Server | Add-Member -MemberType NoteProperty -Name Headers -Value @{"Authorization"="Bearer $($Response.data)"}
            $SupportedApiVersions = @(Get-SgwVersions -Server $Server)
            $Server | Add-Member -MemberType NoteProperty -Name SupportedApiVersions -Value $SupportedApiVersions
            if (($Session.Cookies.GetCookies($BaseURI) | ? { $_.Name -match "CsrfToken" })) {
                $XCsrfToken = $Session.Cookies.GetCookies($BaseUri) | ? { $_.Name -match "CsrfToken" } | select -ExpandProperty Value
                $Server.Headers["X-Csrf-Token"] = $XCsrfToken
            }
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

    $Server | Add-Member -MemberType NoteProperty -Name Session -Value $Session

    if (!$Transient) {
        Set-Variable -Name CurrentSGWServer -Value $Server -Scope Global
    }

    return $Server
}

<#
    .SYNOPSIS
    Connect to StorageGRID Webscale Management Server
    .DESCRIPTION
    Connect to StorageGRID Webscale Management Server
#>
function global:Disconnect-SGWServer {
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
        $Uri = $Server.BaseURI + "/authorize"

        $Method = "DELETE"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
            return
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/config"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/config"
        }

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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/config/management"
        $Method = "PUT"

        $Body = ConvertTo-Json -InputObject @{minApiVersion=$MinApiVersion}
        Write-Verbose "Body: $Body"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }

        $Server.SupportedApiVersions = @(Get-SGWVersions -Server $Server)
       
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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/config/product-version"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/config/product-version"
        }

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
    Retrieves the current API versionsof the management API
    .DESCRIPTION
    Retrieves the current API versionsof the management API
#>
function Global:Get-SGWVersion {
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
        $Uri = $Server.BaseURI + "/versions"
        $Method = "GET"

        Try {
            $Response = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
            $APIVersions = $Response.APIVersion
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }
       
        Write-Output $Response.data
    }
}

## containers ##

# TODO: Implement container cmdlets

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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/deactivated-features"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/deactivated-features"
        }

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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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
        $Body = ConvertTo-Json -InputObject $Body

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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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

## endpoints ##

# TODO: Implement endpoints cmdlets

## endpoint-domain-names ##

<#
    .SYNOPSIS
    Lists endpoint domain names
    .DESCRIPTION
    Lists endpoint domain names
#>
function Global:Get-SGWEndpointDomainNames {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/domain-names"
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
    Change the endpoint domain names
    .DESCRIPTION
    Change the endpoint domain names
#>
function Global:Replace-SGWEndpointDomainNames {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage="List of DNS names to be used as S3/Swift endpoints.")][String[]]$EndpointDomainNames
           )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/domain-names"
        $Method = "PUT"

        $Body = ConvertTo-Json -InputObject $EndpointDomainNames
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

## erasure-coding

# TODO: Implement erasure-coding cmdlets

## expansion ##

<#
    .SYNOPSIS
    Cancels the expansion procedure and resets all user configuration of expansion grid nodes
    .DESCRIPTION
    Cancels the expansion procedure and resets all user configuration of expansion grid nodes
#>
function Global:Stop-SGWExpansion {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion"
        $Method = "DELETE"

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
    Retrieves the status of the current expansion procedure
    .DESCRIPTION
    Retrieves the status of the current expansion procedure
#>
function Global:Get-SGWExpansion {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion"
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
    Initiates the expansion procedure, allowing configuration of the expansion grid nodes
    .DESCRIPTION
    Initiates the expansion procedure, allowing configuration of the expansion grid nodes
#>
function Global:Start-SGWExpansion {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/start"
        $Method = "POST"

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
    Executes the expansion procedure, adding configured grid nodes to the grid
    .DESCRIPTION
    Executes the expansion procedure, adding configured grid nodes to the grid
#>
function Global:Invoke-SGWExpansion {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Passphrase.")][String]$Passphrase,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/expand"
        $Method = "POST"

        $Body = ConvertTo-Json -InputObject @{passphrase=$Passphrase}

        Write-Verbose "Body: $Body"

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

## expansion-nodes ##

<#
    .SYNOPSIS
    Retrieves the list of grid nodes available for expansion
    .DESCRIPTION
    Retrieves the list of grid nodes available for expansion
#>
function Global:Get-SGWExpansionNodes {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/nodes"
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
    Removes a grid node from all procedures; the grid node may be added back in by rebooting it
    .DESCRIPTION
    Removes a grid node from all procedures; the grid node may be added back in by rebooting it
#>
function Global:Remove-SGWExpansionNode {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale node to remove from expansion.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/nodes/$id"
        $Method = "DELETE"

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
    Retrieves a grid node eligbible for expansion
    .DESCRIPTION
    Retrieves a grid node eligbible for expansion
#>
function Global:Get-SGWExpansionNode {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID node eligible for expansion.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/nodes/$id"
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

# TODO: Implement
<#
    .SYNOPSIS
    Configures a grid node expansion
    .DESCRIPTION
    Configures a grid node expansion
#>
function Global:New-SGWExpansionNode {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/start"
        $Method = "POST"

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
    Resets a grid node's configuration and returns it back to pending state
    .DESCRIPTION
    Resets a grid node's configuration and returns it back to pending state
#>
function Global:Reset-SGWExpansionNode {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID node eligible for expansion.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/node/$id"
        $Method = "POST"

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

## expansion-sites ##

<#
    .SYNOPSIS
    Retrieves the list of existing and new sites (empty until expansion is started)
    .DESCRIPTION
    Retrieves the list of existing and new sites (empty until expansion is started)
#>
function Global:Get-SGWExpansionSites {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/sites"
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
    Adds a new site
    .DESCRIPTION
    Adds a new site
#>
function Global:New-SGWExpansionSite {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Name of new site.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$Name,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/site"
        $Method = "POST"

        $Body = ConvertTo-Json -InputObject @{name=$Name}
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

<#
    .SYNOPSIS
    Delete a site
    .DESCRIPTION
    Delete a site
#>
function Global:Remove-SGWExpansionNode {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale site to remove from expansion.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/sites/$id"
        $Method = "DELETE"

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
    Retrieve a site
    .DESCRIPTION
    Retrieve a site
#>
function Global:Get-SGWExpansionSite {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID site.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String[]]$id,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/sites/$id"
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
    Updates the details of a site
    .DESCRIPTION
    Updates the details of a site
#>
function Global:Update-SGWExpansionSite {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID site to be updated.")][String]$ID,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="New ID for the StorageGRID site.")][String]$NewID,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="New name for the StorageGRID site.")][String]$Name,
        [parameter(Mandatory=$False,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/site/$id"
        $Method = "PUT"

        $Body = @{}
        if ($Name) {
            $Body.name = $Name
        }
        if ($NewID) {
            $Body.id = $NewID
        }

        $Body = ConvertTo-Json -InputObject $Body

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

## grid-networks ##

<#
    .SYNOPSIS
    Lists the current Grid Networks
    .DESCRIPTION
    Lists the current Grid Networks
#>
function Global:Get-SGWGridNetworks {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/grid-networks"
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
    Change the Grid Network list
    .DESCRIPTION
    Change the Grid Network list
#>
function Global:Update-SGWGridNetworks {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage="List of grid network Subnets in CIDR format (e.g. 10.0.0.0/16).")][String[]]$Subnets,
        [parameter(Mandatory=$True,
                   Position=2,
                   HelpMessage="StorageGRID Passphrase.")][String]$Passphrase
           )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/grid-networks/update"
        $Method = "POST"

        $Body = @{}
        $Body.passphrase = $Passphrase
        $Body.subnets = $Subnets
        $Body = ConvertTo-Json -InputObject $Body
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

## groups ##

<#
    .SYNOPSIS
    List Groups
    .DESCRIPTION
    List Groups
#>
function Global:Get-SGWGroups {
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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/groups"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/groups"
        }

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

# TODO: Implement adding tenant groups and rename cmdlets
<#
    .SYNOPSIS
    Creates a new Grid Administrator Group
    .DESCRIPTION
    Creates a new Grid Administrator Group
#>
function Global:New-SGWGroup {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Display name of the group.")][String]$displayName,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Display name of the group.")][String]$uniqueName,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="Display name of the group.")][Boolean]$alarmAcknowledgment,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Display name of the group.")][Boolean]$otherGridConfiguration,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Display name of the group.")][Boolean]$gridTopologyPageConfiguration,
        [parameter(
            Mandatory=$False,
            Position=5,
            HelpMessage="Display name of the group.")][Boolean]$tenantAccounts,
        [parameter(
            Mandatory=$False,
            Position=6,
            HelpMessage="Display name of the group.")][Boolean]$changeTenantRootPassword,
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Display name of the group.")][Boolean]$maintenance,
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Display name of the group.")][Boolean]$activateFeatures,
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Display name of the group.")][Boolean]$rootAccess,
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/grid/groups"
            $Method = "POST"

            $Body = @{}
            $Body.displayName = $displayName
            $Body.uniqueName = $uniqueName
            if ($alarmAcknowledgment -or $otherGridConfiguration -or $gridTopologyPageConfiguration -or $tenantAccounts -or $changeTenantRootPassword -or $maintenance -or $activateFeatures -or $rootAccess) {
                $Body.policies = @{}
                $Body.policies.management = @{}
                if ($alarmAcknowledgment) {
                    $Body.policies.management.alarmAcknowledgment = $alarmAcknowledgment
                }
                if ($otherGridConfiguration) {
                    $Body.policies.management.otherGridConfiguration = $otherGridConfiguration
                }
                if ($tenantAccounts) {
                    $Body.policies.management.tenantAccounts = $tenantAccounts
                }
                if ($changeTenantRootPassword) {
                    $Body.policies.management.changeTenantRootPassword = $changeTenantRootPassword
                }
                if ($maintenance) {
                    $Body.policies.management.maintenance = $maintenance
                }
                if ($activateFeatures) {
                    $Body.policies.management.activateFeatures = $activateFeatures
                }
                if ($rootAccess) {
                    $Body.policies.management.rootAccess = $rootAccess
                }
            }
            
            $Body = ConvertTo-Json -InputObject $Body
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
}

<#
    .SYNOPSIS
    Retrieves a local Grid Administrator Group by unique name
    .DESCRIPTION
    Retrieves a local Grid Administrator Group by unique name
#>
function Global:Get-SGWGroupByShortName {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="Short name of the user to retrieve.")][String]$ShortName,
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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/groups/group/$ShortName"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/groups/group/$ShortName"
        }

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
    Retrieves a federated Grid Administrator Group by unique name
    .DESCRIPTION
    Retrieves a federated Grid Administrator Group by unique name
#>
function Global:Get-SGWFederatedGroupByShortName {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="Short name of the user to retrieve.")][String]$ShortName,
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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/groups/federated-group/$ShortName"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/groups/federated-group/$ShortName"
        }

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
    Deletes a single Group
    .DESCRIPTION
    Deletes a single Group
#>
function Global:Delete-SGWGroup {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Group to delete.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$id,
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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/groups/$id"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/groups/$id"
        }

        $Method = "DELETE"

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
    Retrieves a single Group
    .DESCRIPTION
    Retrieves a single Group
#>
function Global:Get-SGWGroup {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Group to retrieve.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$id,
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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/groups/$id"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/groups/$id"
        }

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

# TODO: Implement updating tenant group and rename cmdlet
<#
    .SYNOPSIS
    Updates a single Grid Administrator Group
    .DESCRIPTION
    Updates a single Grid Administrator Group
#>
function Global:Update-SGWGroup {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of the group to be updated.")][String]$ID,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Display name of the group.")][String]$displayName,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="Display name of the group.")][Boolean]$alarmAcknowledgment,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Display name of the group.")][Boolean]$otherGridConfiguration,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Display name of the group.")][Boolean]$gridTopologyPageConfiguration,
        [parameter(
            Mandatory=$False,
            Position=5,
            HelpMessage="Display name of the group.")][Boolean]$tenantAccounts,
        [parameter(
            Mandatory=$False,
            Position=6,
            HelpMessage="Display name of the group.")][Boolean]$changeTenantRootPassword,
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Display name of the group.")][Boolean]$maintenance,
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Display name of the group.")][Boolean]$activateFeatures,
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Display name of the group.")][Boolean]$rootAccess,
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/groups"
        $Method = "POST"

        $Body = @{}
        if ($displayName) {
            $Body.displayName = $displayName
        }
        if ($alarmAcknowledgment -or $otherGridConfiguration -or $gridTopologyPageConfiguration -or $tenantAccounts -or $changeTenantRootPassword -or $maintenance -or $activateFeatures -or $rootAccess) {
            $Body.policies = @{}
            $Body.policies.management = @{}
            if ($alarmAcknowledgment) {
                $Body.policies.management.alarmAcknowledgment = $alarmAcknowledgment
            }
            if ($otherGridConfiguration) {
                $Body.policies.management.otherGridConfiguration = $otherGridConfiguration
            }
            if ($tenantAccounts) {
                $Body.policies.management.tenantAccounts = $tenantAccounts
            }
            if ($changeTenantRootPassword) {
                $Body.policies.management.changeTenantRootPassword = $changeTenantRootPassword
            }
            if ($maintenance) {
                $Body.policies.management.maintenance = $maintenance
            }
            if ($activateFeatures) {
                $Body.policies.management.activateFeatures = $activateFeatures
            }
            if ($rootAccess) {
                $Body.policies.management.rootAccess = $rootAccess
            }
        }
            
        $Body = ConvertTo-Json -InputObject $Body
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

# TODO: Implement replacing tenant group and rename this cmdlet
<#
    .SYNOPSIS
    Replaces a single Grid Administrator Group
    .DESCRIPTION
    Replaces a single Grid Administrator Group
#>
function Global:Replace-SGWGroup {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="ID of the group to be updated.")][String]$ID,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Display name of the group.")][String]$displayName,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="Unique name.")][String]$uniqueName,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="Unique name.")][String]$accountId,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="Unique name.")][Boolean]$federated,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="Unique name.")][String]$groupURN,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Display name of the group.")][Boolean]$alarmAcknowledgment,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Display name of the group.")][Boolean]$otherGridConfiguration,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Display name of the group.")][Boolean]$gridTopologyPageConfiguration,
        [parameter(
            Mandatory=$False,
            Position=5,
            HelpMessage="Display name of the group.")][Boolean]$tenantAccounts,
        [parameter(
            Mandatory=$False,
            Position=6,
            HelpMessage="Display name of the group.")][Boolean]$changeTenantRootPassword,
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Display name of the group.")][Boolean]$maintenance,
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Display name of the group.")][Boolean]$activateFeatures,
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Display name of the group.")][Boolean]$rootAccess,
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server
    )
 
    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/groups/$id"
        $Method = "PUT"

        $Body = @{}
        if ($displayName) {
            $Body.displayName = $displayName
        }
        if ($uniqueName) {
            $Body.uniqueName = $uniqueName
        }
        if ($accountId) {
            $Body.accountId = $accountId
        }
        if ($federated) {
            $Body.federated = $federated
        }
        if ($groupURN) {
            $Body.groupURN = $groupURN
        }
        if ($alarmAcknowledgment -or $otherGridConfiguration -or $gridTopologyPageConfiguration -or $tenantAccounts -or $changeTenantRootPassword -or $maintenance -or $activateFeatures -or $rootAccess) {
            $Body.policies = @{}
            $Body.policies.management = @{}
            if ($alarmAcknowledgment) {
                $Body.policies.management.alarmAcknowledgment = $alarmAcknowledgment
            }
            if ($otherGridConfiguration) {
                $Body.policies.management.otherGridConfiguration = $otherGridConfiguration
            }
            if ($tenantAccounts) {
                $Body.policies.management.tenantAccounts = $tenantAccounts
            }
            if ($changeTenantRootPassword) {
                $Body.policies.management.changeTenantRootPassword = $changeTenantRootPassword
            }
            if ($maintenance) {
                $Body.policies.management.maintenance = $maintenance
            }
            if ($activateFeatures) {
                $Body.policies.management.activateFeatures = $activateFeatures
            }
            if ($rootAccess) {
                $Body.policies.management.rootAccess = $rootAccess
            }
        }
            
        $Body = ConvertTo-Json -InputObject $Body
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
            ValueFromPipelineByPropertyName=$True)][String]$id,
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
        if ($Server.APIVersion -gt 1) {
            Throw "This Cmdlet is only supported with API Version 1"
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
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

## health ##

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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
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

## identity-source ##

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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/identity-source"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/identity-source"
        }

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
            ValueFromPipelineByPropertyName=$True)][String]$Id,
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
            HelpMessage="Identity Source Username and password")][PSCredential]$Credential,
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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/identity-source"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/identity-source"
        }

        $Method = "PUT"

        $Username = $Credential.UserName -replace '([a-zA-Z0-9])\\([a-zA-Z0-9])','$1\\\\$2'
        $Password = $Credential.GetNetworkCredential().Password

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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/identity-source/synchronize"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/identity-source/synchronize"
        }

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

## ilm ##

# TODO: Implement missing cmdlets and check existing cmdlets

<#
    .SYNOPSIS
    Evaluates proposed ILM policy
    .DESCRIPTION
    Evaluates proposed ILM policy
#>
function Global:Invoke-SGWIlmEvaluate {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="The object API that the provided object was evaluated against.")][String][ValidateSet('cdmi', 's3', 'swift')]$API,
        [parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage="Protocol-specific object identifier (e.g. bucket/key/1).")][String]$ObjectID,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="Switch indicating that ILM evaluation should occur immediately.")][Switch]$Now,
        [parameter(Mandatory=$False,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/ilm-evaluate"
        $Method = "POST"

        $Body = @{}
        $Body.objectID = $ObjectID
        if ($API) {
            $Body.api = $API
        }
        if ($Now) {
            $Body.now = Get-Date -Format u
        }

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

<#
    .SYNOPSIS
    Lists metadata available for creating an ILM rule
    .DESCRIPTION
    Lists metadata available for creating an ILM rule
#>
function Global:Get-SGWIlmMetadata {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="The object API that the provided object was evaluated against.")][String][ValidateSet('cdmi', 's3', 'swift')]$API,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/ilm-metadata?api=$api"
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
    Lists ILM rules
    .DESCRIPTION
    Lists ILM rules
#>
function Global:Get-SGWIlmRules {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/ilm-rules"
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

## license ##

<#
    .SYNOPSIS
    Retrieves the grid license
    .DESCRIPTION
    Retrieves the grid license
#>
function Global:Get-SGWLicense {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/license"
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
    Update the license
    .DESCRIPTION
    Update the license
#>
function Global:Update-SGWLicense {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale license.",
                   ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)][String]$License,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="StorageGRID Webscale Passphrase.")][String]$Passphrase,
        [parameter(Mandatory=$False,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/license/update"
        $Method = "POST"

        $Body = @{}
        $Body.passphrase = $Passphrase
        $Body.license = $License

        $Body = ConvertTo-Json -InputObject $Body
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

## logs ##

# TODO: Implement logs cmdlets

## metrics ##

<#
    .SYNOPSIS
    Retrieves the metric names
    .DESCRIPTION
    Retrieves the metric names
#>
function Global:Get-SGWMetricNames {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/metric-names"
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
    Performs an instant metric query at a single point in time
    .DESCRIPTION
    Performs an instant metric query at a single point in time
#>
function Global:Get-SGWMetricQuery {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage="Prometheus query string.")][String]$Query,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="Query start, default current time (date-time).")][DateTime]$Time,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="Timeout in seconds.")][Int]$Timeout=120
           )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SGWServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/metric-query"
        $Method = "GET"

        $Uri += "?query=$Query"

        if ($Time) {
            $Uri += "&time=$(Get-Date -Format o $Time.ToUniversalTime())"
        }

        if ($Timeout) {
            $Uri += "&timeout=$($Timeout)s"
        }


        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }

        $Metrics = $Result.data.result | % { [PSCustomObject]@{Metric=$_.metric.__name__;Instance=$_.metric.instance;Time=(ConvertFrom-UnixTimestamp -Unit Seconds -Timestamp $_.value[0]);Value=$_.value[1]} }
       
        Write-Output $Metrics
    }
}

# TODO: Implement metrics cmdlets

## ntp-servers ##

<#
    .SYNOPSIS
    Lists configured external NTP servers
    .DESCRIPTION
    Lists configured external NTP servers
#>
function Global:Get-SGWNtpServers {
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/ntp-servers"
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
    Change the external NTP servers used by the grid
    .DESCRIPTION
    Change the external NTP servers used by the grid
#>
function Global:Update-SGWNtpServers {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale license.")][String[]]$Servers,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="StorageGRID Webscale Passphrase.")][String]$Passphrase,
        [parameter(Mandatory=$False,
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
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }
 
    Process {
        $Uri = $Server.BaseURI + "/grid/ntp-servers/update"
        $Method = "POST"

        $Body = @{}
        $Body.passphrase = $Passphrase
        $Body.servers = $Servers

        $Body = ConvertTo-Json -InputObject $Body
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

## objects ##

## recovery ##

# TODO: Implement recovery Cmdlets

## recovery-package ##

# TODO: Implement recovery-package Cmdlets

## regions ##

# TODO: implement regions cmdlets

## server-certificate ##

# TODO: Implement server-certificate Cmdlets

## users ##

<#
    .SYNOPSIS
    Retrieve all StorageGRID Users
    .DESCRIPTION
    Retrieve all StorageGRID Users
#>
function Global:Get-SGWUsers {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="User type (default local).")][ValidateSet("local","federated")][String]$Type="local",
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="Maximum number of results.")][Int]$Limit=0,
        [parameter(Mandatory=$False,
                   Position=3,
                   HelpMessage="Pagination offset (value is Account's id).")][String]$Marker,
        [parameter(Mandatory=$False,
                   Position=4,
                   HelpMessage="if set, the marker element is also returned.")][Switch]$IncludeMarker,
        [parameter(Mandatory=$False,
                   Position=5,
                   HelpMessage="pagination order (desc requires marker).")][ValidateSet("asc","desc")][String]$Order="asc"
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
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + '/org/users'
        }
        else {
            $Uri = $Server.BaseURI + '/grid/users'
        }

        $Method = "GET"

        if ($Limit -eq 0) {
            $Query = "?limit=25"
        }
        else {
            $Query = "?limit=$Limit"
        }
        if ($Type) { $Query += "&type=$Type" }
        if ($Marker) { $Query += "&marker=$Marker" }
        if ($IncludeMarker) { $Query += "&includeMarker=true" }
        if ($Order) { $Query += "&order=$Order" }

        $Uri += $Query
        
        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $($responseBody.message)"
            return
        }

        $Result.data | Add-Member -MemberType AliasProperty -Name userId -Value id

        Write-Output $Result.data

        if ($Limit -eq 0 -and $Result.data.count -eq 25) {
            Get-SGWAccounts -Server $Server -Limit $Limit -Marker ($Result.data | select -last 1 -ExpandProperty id) -IncludeMarker:$IncludeMarker -Order $Order
        }              
    }
}

# TODO: Implement users Cmdlets

## s3 ##

<#
    .SYNOPSIS
    Retrieve StorageGRID Webscale Account S3 Access Keys
    .DESCRIPTION
    Retrieve StorageGRID Webscale Account S3 Access Keys
#>
function Global:Get-SGWS3AccessKeys {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to get S3 Access Keys for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="ID of a StorageGRID Webscale User.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$UserId,
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
        if (!$Server.AccountId -and !$Server.SupportedApiVersions.Contains(1)) {
            Throw "This cmdlet requires API Version 1 support if connection to server was not made with a tenant account id. Either use Connect-SgwServer with the AccountId parameter or enable API version 1 with Update-SGWConfigManagement -MinApiVersion 1"
        }
    }
 
    Process {
        if ($Server.AccountId) {
            if ($UserId) {
                $Uri = $Server.BaseURI + "/org/users/$UserId/s3-access-keys"
            }
            else {
                $Uri = $Server.BaseURI + "/org/users/current-user/s3-access-keys"
            }
        }
        else {
            if ($AccountId) {
                $Uri = $Server.BaseURI + "/grid/accounts/$AccountId/s3-access-keys"
            }
            else {
                Throw "Account ID required. Rerun command with AccountId parameter"
            }
        }

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
    Retrieve a StorageGRID Webscale Account S3 Access Key
    .DESCRIPTION
    Retrieve a StorageGRID Webscale Account S3 Access Key
#>
function Global:Get-SGWS3AccessKey {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="ID of a StorageGRID Webscale Account to get S3 Access Keys for",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="ID of a StorageGRID Webscale User.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$UserId,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="Access Key to delete.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$AccessKey,
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
        if (!$Server.AccountId -and !$Server.SupportedApiVersions.Contains(1)) {
            Throw "This cmdlet requires API Version 1 support if connection to server was not made with a tenant account id. Either use Connect-SgwServer with the AccountId parameter or enable API version 1 with Update-SGWConfigManagement -MinApiVersion 1"
        }
    }
 
    Process {
        if ($Server.AccountId) {
            if ($UserId) {
                $Uri = $Server.BaseURI + "/org/users/$UserId/s3-access-keys/$AccessKey"
            }
            else {
                $Uri = $Server.BaseURI + "/org/users/current-user/s3-access-keys/$AccessKey"
            }
        }
        else {
            if ($AccountId) {
                $Uri = $Server.BaseURI + "/grid/accounts/$AccountId/s3-access-keys/$AccessKey"
            }
            else {
                Throw "Account ID required. Rerun command with id parameter"
            }
        }

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
    Create a new StorageGRID Webscale Account S3 Access Key
    .DESCRIPTION
    Create a new StorageGRID Webscale Account S3 Access Key
#>
function Global:New-SGWS3AccessKey {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="Id of the StorageGRID Webscale Account to create new S3 Access Key for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="ID of a StorageGRID Webscale User.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$UserId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="Expiration date of the S3 Access Key.")][DateTime]$Expires,
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
        if (!$Server.AccountId -and !$Server.SupportedApiVersions.Contains(1)) {
            Throw "This cmdlet requires API Version 1 support if connection to server was not made with a tenant account id. Either use Connect-SgwServer with the AccountId parameter or enable API version 1 with Update-SGWConfigManagement -MinApiVersion 1"
        }
        if ($Expires) {
            $ExpirationDate = Get-Date -Format o $Expires.ToUniversalTime()
        }
    }
 
    Process {
        if ($Server.AccountId) {
            if ($UserId) {
                $Uri = $Server.BaseURI + "/org/users/$UserId/s3-access-keys"
            }
            else {
                $Uri = $Server.BaseURI + "/org/users/current-user/s3-access-keys"
            }
        }
        else {
            if ($AccountId) {
                $Uri = $Server.BaseURI + "/grid/accounts/$AccountId/s3-access-keys"
            }
            else {
                Throw "Account ID required. Rerun command with id parameter"
            }
        }

        $Method = "POST"

        $Body = "{}"
        if ($Expires) { 
            $Body = ConvertTo-Json -InputObject @{"expires"="$ExpirationDate"}
            Write-Verbose "Body:`n$Body"
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
function Global:Remove-SGWS3AccessKey {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Id of the StorageGRID Webscale Account to delete S3 Access Key for.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="ID of a StorageGRID Webscale User.",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$UserId,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="S3 Access Key ID to be deleted,",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)][String]$AccessKey,
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
        if (!$Server.AccountId -and !$Server.SupportedApiVersions.Contains(1)) {
            Throw "This cmdlet requires API Version 1 support if connection to server was not made with a tenant account id. Either use Connect-SgwServer with the AccountId parameter or enable API version 1 with Update-SGWConfigManagement -MinApiVersion 1"
        }
    }
 
    Process {
        if ($Server.AccountId) {
            if ($UserId) {
                $Uri = $Server.BaseURI + "/org/users/$UserId/s3-access-keys/$AccessKey"
            }
            else {
                $Uri = $Server.BaseURI + "/org/users/current-user/s3-access-keys/$AccessKey"
            }
        }
        else {
            if ($AccountId) {
                $Uri = $Server.BaseURI + "/grid/accounts/$AccountId/s3-access-keys/$AccessKey"
            }
            else {
                Throw "Account ID required. Rerun command with AccountId parameter"
            }
        }

        $Method = "DELETE"

        try {
            $Result = Invoke-RestMethod -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$Method to $Uri failed with Exception $($_.Exception.Message) `n $responseBody"
        }  
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
            $OID = (Get-SGWTopologyHealth -Server $Server).oid
        }

        $Method = "GET"
        $Uri = "https://$($Server.Name)/NMS/render/JSP/DoXML.jsp?requestType=RPTX&mode=PAGE&start=$StartTimeString&end=$EndTimeString&attr=$AttributeCode&attrIndex=1&oid=$OID&type=text"

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
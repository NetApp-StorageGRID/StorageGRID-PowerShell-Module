# Workaround to allow Powershell to accept untrusted certificates
add-type @"
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
                   HelpMessage="This cmdlet always tries to establish a secure HTTPS connection to the StorageGRID Webscale Management Server, but it will fall back to HTTP if necessary. Specify -HTTP to skip the HTTPS connection attempt and only try HTTP.")][Switch]$HTTP,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="This cmdlet always tries to establish a secure HTTPS connection to the StorageGRID Webscale Management Server, but it will fall back to HTTP if necessary. Specify -HTTPS to fail the connection attempt in that case rather than fall back to HTTP.")][Switch]$HTTPS,
        [parameter(Mandatory=$False,
                   Position=3,
                   HelpMessage="If the StorageGRID Webscale Management Server certificate cannot be verified, the connection will fail. Specify -Insecure to ignore the validity of the StorageGRID Webscale Management Server certificate.")][Switch]$Insecure,
        [parameter(Position=4,
                   Mandatory=$False,
                   HelpMessage="Specify -Transient to not set the global variable `$CurrentOciServer.")][Switch]$Transient
    )

    # check if untrusted SSL certificates should be ignored
    if ($Insecure) {
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }

    # check if proxy is used
    $ProxyRegistry = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $ProxySettings = Get-ItemProperty -Path $ProxyRegistry
    if ($ProxySettings.ProxyEnable) {
        Write-Warning "Proxy Server $($ProxySettings.ProxyServer) configured in Internet Explorer may be used to connect to the OCI server!"
    }
    if ($ProxySettings.AutoConfigURL) {
        Write-Warning "Proxy Server defined in automatic proxy configuration script $($ProxySettings.AutoConfigURL) configured in Internet Explorer may be used to connect to the OCI server!"
    }

    $Server = New-Object -TypeName PSCustomObject
    $Server | Add-Member -MemberType NoteProperty -Name Name -Value $Name
    $Server | Add-Member -MemberType NoteProperty -Name Credential -Value $Credential

    $Body = @"
{
    "username": "$($Credential.UserName)", 
    "password": "$($Credential.GetNetworkCredential().Password)"
}
"@
 
    if ($HTTPS -or !$HTTP) {
        Try {
            $Server | Add-Member -MemberType NoteProperty -Name BaseURI -Value "https://$Name"
            $Response = Invoke-RestMethod -Method POST -Uri "$($Server.BaseURI)/api/v1/authorize" -TimeoutSec 10 -ContentType "application/json" -Body $body
            if ($Response.status -eq "success") {
                $Server | Add-Member -MemberType NoteProperty -Name APIVersion -Value $Response.apiVersion
                $Server | Add-Member -MemberType NoteProperty -Name Headers -Value @{"Authorization"="Bearer $($Response.data)"}
            }
            if (!$Transient) {
                Set-Variable -Name CurrentSGWServer -Value $Server -Scope Global
            }
 
            return $Server
        }
        Catch {
            if ($_.Exception.Message -match "Unauthorized") {
                Write-Error "Authorization for $($Server.BaseURI)/api/v1/authorize with user $($Credential.UserName) failed"
                return
            }
            else {
                if ($HTTPS) {
                    $result = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($result)
                    $reader.BaseStream.Position = 0
                    $reader.DiscardBufferedData()
                    $responseBody = $reader.ReadToEnd()
                    if ($responseBody.StartsWith('{')) {
                        $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                    }
                    Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
                    return
                }
                else {
                    Write-Warning "Login to $BaseURI/api/v1/authorize failed via HTTPS protocol"
                    $HTTP = $True
                }
            }
        }
    }

    if ($HTTP) {
        Try {
            $Server | Add-Member -MemberType NoteProperty -Name BaseURI -Value "http://$Name" -Force
            $Response = Invoke-RestMethod -Method POST -Uri "$($Server.BaseURI)/api/v1/authorize" -TimeoutSec 10 -ContentType "application/json" -Body $Body
            if ($Response.status -eq "success") {
                $Server | Add-Member -MemberType NoteProperty -Name APIVersion -Value $Response.apiVersion
                $Server | Add-Member -MemberType NoteProperty -Name Headers -Value @{"Authorization"="Bearer $($Response.data)"}
            }
            
            if (!$Transient) {
                Set-Variable -Name CurrentSGWServer -Value $Server -Scope Global
            }
 
            return $Server
        }
        Catch {
            if ($_.Exception.Message -match "Unauthorized") {
                Write-Error "Authorization for $($Server.BaseURI)/api/v1/authorize with user $($Credential.UserName) failed"
                return
            }
            else {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
                return
            }
        }
    }
}

<#
    .SYNOPSIS
    Disconnect from StorageGRID Webscale Management Server
    .DESCRIPTION
    Disconnect from StorageGRID Webscale Management Server
#>
function Global:Disconnect-SGWServer {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSGWServer object will be used.")][PSCustomObject[]]$Server
    )
 
    Process {
        if (!$Server) {
            $Server = $Global:CurrentSGWServer
            $DeleteCurrentSGWServer = $true
        }
        if (!$Server) {
            Write-Error "No StorageGRID Webscale Management Server found. Please run Connect-SGWServer to continue."
        }

        foreach ($Server in $Server) {
            $Uri = $Server.BaseURI + '/api/v1/authorize'

            try {
                $Result = Invoke-RestMethod -Method DELETE -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
            }

            if ($DeleteCurrentSGWServer) {
                $Global:CurrentSGWServer = $null
            }
       
            Write-Host "Succesfully disconnected from StorageGRID Management Server $($Server.Name)"
        }
    }
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
        $Uri = $Server.BaseURI + '/api/v1/grid/accounts'

        try {
            $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $result = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($result)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd()
            if ($responseBody.StartsWith('{')) {
                $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
            }
            Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$id"

            try {
                $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts"

            $Body = @"
{
    "name": "$Name",
    "capabilities": [ $Capabilities ]
}
"@

            try {
                $Body
                $Result = Invoke-RestMethod -Method POST -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
function Global:Delete-SGWAccount {
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
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$id"

            try {
                $Result = Invoke-RestMethod -Method DELETE -Uri $Uri -Headers $Server.Headers
                Write-Host "Successfully deleted account with ID $id"
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
            }
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
            HelpMessage="Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).")][String]$Capabilities,
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
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$id"

            $Body = ""

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

            try {
                $Result = Invoke-RestMethod -Method PUT -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$id/swift-admin-password"

            $Body = @"
{
  "password": "$NewPassword",
  "currentPassword": "$OldPassword"
}
"@
            try {
                $Result = Invoke-RestMethod -Method POST -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$id/usage"

            try {
                $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$id/groups"

            try {
                $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$id/usage"

            try {
                $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$id/s3-access-keys"

            try {
                $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$($AccountId[$Index])/s3-access-keys/$($Id[$Index])"

            try {
                $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Server.Headers
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
        $Id = @($Id)
        foreach ($Id in $Id) {
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$id/s3-access-keys"

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
                $Body
                $Result = Invoke-RestMethod -Method POST -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json"
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Delete a StorageGRID Webscale Account S3 Access Key
    .DESCRIPTION
    Delete a StorageGRID Webscale Account S3 Access Key
#>
function Global:Delete-SGWAccountS3AccessKey {
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
            $Uri = $Server.BaseURI + "/api/v1/grid/accounts/$($AccountId[$Index])/s3-access-keys/$($Id[$Index])"

            try {
                $Result = Invoke-RestMethod -Method DELETE -Uri $Uri -Headers $Server.Headers
                Write-Host "Successfully deleted S3 Access Key $AccessKey for ID $Id"
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
        $Uri = $Server.BaseURI + "/api/v1/grid/identity-source"

        try {
            $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Server.Headers
        }
        catch {
            $result = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($result)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd()
            if ($responseBody.StartsWith('{')) {
                $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
            }
            Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
            $Uri = $Server.BaseURI + "/api/v1/grid/identity-source"

            try {
                $Result = Invoke-RestMethod -Method PUT -Uri $Uri -Headers $Server.Headers -Body $Body
            }
            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                if ($responseBody.StartsWith('{')) {
                    $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
                }
                Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
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
        $Uri = $Server.BaseURI + "/api/v1/grid/identity-source/synchronize"

        try {
            $Result = Invoke-RestMethod -Method POST -Uri $Uri -Headers $Server.Headers -Body ""
            Write-Host "Successfully synchronized users and groups of identity sources"
        }
        catch {
            $result = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($result)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd()
            if ($responseBody.StartsWith('{')) {
                $responseBody = $responseBody | ConvertFrom-Json | ConvertTo-Json
            }
            Write-Error "GET to $Uri failed with status code $($_.Exception.Response.StatusCode) and response body:`n$responseBody"
        }
       
        Write-Output $Result.data
    }
}

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

function global:Connect-S3MgmtServer {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=$True,
                   Position=0,
                   HelpMessage="The name of the S3 Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.")][String]$Name,
        [parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage="A System.Management.Automation.PSCredential object containing the credentials needed to log into the S3 server.")][System.Management.Automation.PSCredential]$Credential,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="This cmdlet always tries to establish a secure HTTPS connection to the S3 server, but it will fall back to HTTP if necessary. Specify -HTTP to skip the HTTPS connection attempt and only try HTTP.")][Switch]$HTTP,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="This cmdlet always tries to establish a secure HTTPS connection to the S3 server, but it will fall back to HTTP if necessary. Specify -HTTPS to fail the connection attempt in that case rather than fall back to HTTP.")][Switch]$HTTPS,
        [parameter(Mandatory=$False,
                   Position=3,
                   HelpMessage="If the S3 server certificate cannot be verified, the connection will fail. Specify -Insecure to ignore the validity of the S3 server certificate.")][Switch]$Insecure,
        [parameter(Position=4,
                   Mandatory=$False,
                   HelpMessage="Specify -Transient to not set the global variable `$CurrentOciServer.")][Switch]$Transient
    )
 
    $LF = "`r`n"

    $boundary = [System.Guid]::NewGuid().ToString()
  
    $bodyLines = (
        "--$boundary",
        "Content-Disposition: form-data; name=`"username`"$LF",
        $Credential.UserName,
        "--$boundary",
        "Content-Disposition: form-data; name=`"password`"$LF",
        $Credential.GetNetworkCredential().Password,
        "--$boundary--$LF"
     ) -join $LF

    if ($Insecure) {
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
 
    if ($HTTPS) {
        Try {
            $BaseURI = "https://$Name"
            $Response = Invoke-RestMethod -Method Post -Uri "$BaseURI/api/v1/authorize" -TimeoutSec 10 -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
            $APIVersion = $Response.apiVersion
        }
        Catch {
            if ($_.Exception.Message -match "Unauthorized") {
                Write-Error "Authorization for $BaseURI/api/v1/authorize with user $($Credential.UserName) failed"
                return
            }
            else {
                Write-Error "Login to $BaseURI/api/v1/authorize failed via HTTPS protocol, but HTTPS was enforced"
                return
            }
        }
    }
    elseif ($HTTP) {
        Try {
            $BaseURI = "https://$Name"
            $Response = Invoke-RestMethod -Method Post -Uri "$BaseURI/api/v1/authorize" -TimeoutSec 10 -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
            $APIVersion = $Response.apiVersion
        }
        Catch {
            if ($_.Exception.Message -match "Unauthorized") {
                Write-Error "Authorization for $BaseURI/api/v1/authorize with user $($Credential.UserName) failed"
                return
            }
            else {
                Write-Error "Login to $BaseURI/api/v1/authorize failed via HTTP protocol, but HTTP was enforced"
                return
            }
        }
    }
    else {
        Try {
            $BaseURI = "https://$Name"
            $Response = Invoke-RestMethod -Method Post -Uri "$BaseURI/api/v1/authorize" -TimeoutSec 10 -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
            $APIVersion = $Response.apiVersion
            $HTTPS = $True
        }
        Catch {
            if ($_.Exception.Message -match "Unauthorized") {
                Write-Error "Authorization for $BaseURI/api/v1/authorize with user $($Credential.UserName) failed"
                return
            }
            else {
                Write-Warning "Login to $BaseURI/rest/v1/login failed via HTTPS protocol, falling back to HTTP protocol."
                Try {
                    $BaseURI = "http://$Name"
                    $Response = Invoke-RestMethod -Method Post -Uri "$BaseURI/api/v1/authorize" -TimeoutSec 10 -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
                    $APIVersion = $Response.apiVersion
                    $HTTP = $True
                }
                Catch {
                    if ($_.Exception.Message -match "Unauthorized") {
                        Write-Error "Authorization for $BaseURI/api/v1/authorize with user $($Credential.UserName) failed"
                        return
                    }
                    else {
                        Write-Error "Login to $BaseURI/api/v1/authorize failed via HTTP protocol."
                        return
                    }
                }
            }
        }
    }

    $Headers = @{"Authorization"="Bearer $($Response.data)"}
 
    $Server = New-Object -TypeName psobject
    $Server | Add-Member -MemberType NoteProperty -Name Name -Value $Name
    $Server | Add-Member -MemberType NoteProperty -Name BaseURI -Value $BaseURI
    $Server | Add-Member -MemberType NoteProperty -Name Credential -Value $Credential
    $Server | Add-Member -MemberType NoteProperty -Name Headers -Value $Headers
    $Server | Add-Member -MemberType NoteProperty -Name APIVersion -Value $APIVersion
 
    if (!$Transient) {
        Set-Variable -Name CurrentS3MgmtServer -Value $Server -Scope Global
    }
 
    return $Server
}

<#
    .SYNOPSIS
    Retrieve all S3 Accounts
    .DESCRIPTION
    Retrieve all S3 Accounts
#>
function Global:Get-S3Accounts {
    [CmdletBinding()]

    PARAM ()

    Begin {
        if (!$CurrentS3MgmtServer) {
            Write-Error "No S3 management server found. Please run Connect-S3MgtServer to continue."
        }
        $Result = $null
    }
 
    Process {
        $Uri = $CurrentS3MgmtServer.BaseURI + '/api/v1/service-provider/s3-accounts'


 
        try {
            $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $CurrentS3MgmtServer.Headers
        }
        catch {
            $Response = $_.Exception.Response
            if ($Response) {
                $Result = $Response.GetResponseStream()
                $Reader = New-Object System.IO.StreamReader($Result)
                $responseBody = $reader.ReadToEnd()
            }
            Write-Error "GET to $Uri failed with response:`n$responseBody"
        }
       
        Write-Output $Result.data
    }
}

<#
    .SYNOPSIS
    Retrieve an S3 Account
    .DESCRIPTION
    Retrieve an S3 Account
#>
function Global:Get-S3Account {
    [CmdletBinding()]

    PARAM (
    [parameter(Mandatory=$True,
                Position=0,
                HelpMessage="ID of S3 Account to get information for",
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)][String[]]$id
    )
 
    Begin {
        if (!$CurrentS3MgmtServer) {
            Write-Error "No S3 management server found. Please run Connect-S3MgtServer to continue."
        }
        $Result = $null
    }
   
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $CurrentS3MgmtServer.BaseURI + "/api/v1/service-provider/s3-accounts/$id"
 
            try {
                $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $CurrentS3MgmtServer.Headers
            }
            catch {
                $Response = $_.Exception.Response
                if ($Response) {
                    $Result = $Response.GetResponseStream()
                    $Reader = New-Object System.IO.StreamReader($Result)
                    $responseBody = $reader.ReadToEnd()
                }
                Write-Error "GET to $Uri failed with response:`n$responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Retrieve S3 Account Usage
    .DESCRIPTION
    Retrieve S3 Account Usage
#>
function Global:Get-S3AccountUsage {
    [CmdletBinding()]

    PARAM (
    [parameter(Mandatory=$True,
                Position=0,
                HelpMessage="ID of S3 Account to get information for",
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)][String[]]$id
    )
 
    Begin {
        if (!$CurrentS3MgmtServer) {
            Write-Error "No S3 management server found. Please run Connect-S3MgtServer to continue."
        }
        $Result = $null
    }
   
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $CurrentS3MgmtServer.BaseURI + "/api/v1/service-provider/s3-accounts/$id/usage"
 
            try {
                $Result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $CurrentS3MgmtServer.Headers
            }
            catch {
                $Response = $_.Exception.Response
                if ($Response) {
                    $Result = $Response.GetResponseStream()
                    $Reader = New-Object System.IO.StreamReader($Result)
                    $responseBody = $reader.ReadToEnd()
                }
                Write-Error "GET to $Uri failed with response:`n$responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Update an S3 Account
    .DESCRIPTION
    Update an S3 Account
#>
function Global:Update-S3Account {
    [CmdletBinding()]

    PARAM (
    [parameter(Mandatory=$True,
               Position=0,
               HelpMessage="ID of S3 Account to update",
               ValueFromPipeline=$True,
               ValueFromPipelineByPropertyName=$True)][String[]]$id,
    [parameter(Mandatory=$True,
               Position=1,
               HelpMessage="New name for S3 Account")][String[]]$Name

    )
 
    Begin {
        $Result = $null
    }
   
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $CurrentS3MgmtServer.BaseURI + "/api/v1/service-provider/s3-accounts/$id"
 
            try {
                $Result = Invoke-RestMethod -Method PATCH -Uri $Uri -Headers $CurrentS3MgmtServer.Headers -Body "{`"name`":`"$Name`"}"
            }
            catch {
                $Response = $_.Exception.Response
                if ($Response) {
                    $Result = $Response.GetResponseStream()
                    $Reader = New-Object System.IO.StreamReader($Result)
                    $responseBody = $reader.ReadToEnd()
                }
                Write-Error "GET to $Uri failed with response:`n$responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Restore S3 Account Secret Key
    .DESCRIPTION
    Restore S3 Account Secret Key
#>
function Global:Restore-S3AccountSecretKey {
    [CmdletBinding()]

    PARAM (
    [parameter(Mandatory=$True,
               Position=0,
               HelpMessage="ID of S3 Account to update",
               ValueFromPipeline=$True,
               ValueFromPipelineByPropertyName=$True)][String[]]$id
    )
 
    Begin {
        $Result = $null
    }
   
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $CurrentS3MgmtServer.BaseURI + "/api/v1/service-provider/s3-accounts/$id/regenerate-keys"
 
            try {
                $Result = Invoke-RestMethod -Method POST -Uri $Uri -Headers $CurrentS3MgmtServer.Headers
            }
            catch {
                $Response = $_.Exception.Response
                if ($Response) {
                    $Result = $Response.GetResponseStream()
                    $Reader = New-Object System.IO.StreamReader($Result)
                    $responseBody = $reader.ReadToEnd()
                }
                Write-Error "PATCH to $Uri failed with response:`n$responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Create an S3 Account
    .DESCRIPTION
    Create an S3 Account
#>
function Global:Create-S3Account {
    [CmdletBinding()]

    PARAM (
    [parameter(Mandatory=$True,
               Position=0,
               HelpMessage="ID of S3 Account to update",
               ValueFromPipeline=$True,
               ValueFromPipelineByPropertyName=$True)][String[]]$Name
    )
 
    Begin {
        $Result = $null
    }
   
    Process {
        $Name = @($Name)
        foreach ($Name in $Name) {
            $Uri = $CurrentS3MgmtServer.BaseURI + "/api/v1/service-provider/s3-accounts"
 
            try {
                $Result = Invoke-RestMethod -Method POST -Uri $Uri -Headers $CurrentS3MgmtServer.Headers -Body "{`"name`":`"$Name`"}"
            }
            catch {
                $Response = $_.Exception.Response
                if ($Response) {
                    $Result = $Response.GetResponseStream()
                    $Reader = New-Object System.IO.StreamReader($Result)
                    $responseBody = $reader.ReadToEnd()
                }
                Write-Error "POST to $Uri failed with response:`n$responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}

<#
    .SYNOPSIS
    Delete an S3 Account
    .DESCRIPTION
    Delete an S3 Account
#>
function Global:Delete-S3Account {
    [CmdletBinding()]

    PARAM (
    [parameter(Mandatory=$True,
                Position=0,
                HelpMessage="ID of S3 Account to delete",
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)][String[]]$id
    )
 
    Begin {
        if (!$CurrentS3MgmtServer) {
            Write-Error "No S3 management server found. Please run Connect-S3MgtServer to continue."
        }
        $Result = $null
    }
   
    Process {
        $id = @($id)
        foreach ($id in $id) {
            $Uri = $CurrentS3MgmtServer.BaseURI + "/api/v1/service-provider/s3-accounts/$id"
 
            try {
                $Result = Invoke-RestMethod -Method DELETE -Uri $Uri -Headers $CurrentS3MgmtServer.Headers
            }
            catch {
                $Response = $_.Exception.Response
                if ($Response) {
                    $Result = $Response.GetResponseStream()
                    $Reader = New-Object System.IO.StreamReader($Result)
                    $responseBody = $reader.ReadToEnd()
                }
                Write-Error "GET to $Uri failed with response:`n$responseBody"
            }
       
            Write-Output $Result.data
        }
    }
}
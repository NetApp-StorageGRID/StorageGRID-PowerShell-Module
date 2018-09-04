$SGW_PROFILE_PATH = "$HOME/.sgw/"
$SGW_CREDENTIALS_FILE = $SGW_PROFILE_PATH + "credentials"

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
        if ($jsonItem.PSObject.TypeNames -match "Array") {
            return ParseJsonArray($jsonItem)
        }
        elseif ($jsonItem.PSObject.TypeNames -match "Dictionary") {
            return ParseJsonObject([HashTable]$jsonItem)
        }
        else {
            return $jsonItem
        }
    }

    function ParseJsonObject($jsonObj) {
        $Response = New-Object -TypeName PSCustomObject
        foreach ($key in $jsonObj.Keys) {
            $item = $jsonObj[$key]
            if ($item) {
                $parsedItem = ParseItem $item
            }
            else {
                $parsedItem = $null
            }
            $Response | Add-Member -MemberType NoteProperty -Name $key -Value $parsedItem
        }
        return $Response
    }

    function ParseJsonArray($jsonArray) {
        $Response = @()
        $jsonArray | ForEach-Object {
            $Response += ,(ParseItem $_)
        }
        return $Response
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

function ParseErrorForResponseBody($Error) {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if ($Error.Exception.Response) {
            $Reader = New-Object System.IO.StreamReader($Error.Exception.Response.GetResponseStream())
            $Reader.BaseStream.Position = 0
            $Reader.DiscardBufferedData()
            $ResponseBody = $Reader.ReadToEnd()
            if ( $ResponseBody.StartsWith('{')) {
                $ResponseBody = $ResponseBody | ConvertFrom-Json | ConvertTo-Json
            }
            return $ResponseBody
        }
    }
    else {
        return $Error.ErrorDetails.Message
    }
}

# helper function to convert datetime to unix timestamp
function ConvertTo-UnixTimestamp {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $True,
                Position = 0,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Date to be converted.")][DateTime[]]$Date,
        [parameter(Mandatory = $True,
                Position = 1,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Unit of timestamp.")][ValidateSet("Seconds", "Milliseconds")][String]$Unit = "Milliseconds"
    )

    BEGIN {
        $epoch = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0
    }

    PROCESS {
        if ($Unit = "Seconds") {
            Write-Output ([math]::truncate($Date.ToUniversalTime().Subtract($epoch).TotalSeconds))
        }
        else {
            Write-Output ([math]::truncate($Date.ToUniversalTime().Subtract($epoch).TotalMilliSeconds))
        }
    }
}

# helper function to convert unix timestamp to datetime
function ConvertFrom-UnixTimestamp {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $True,
                Position = 0,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Timestamp to be converted.")][String]$Timestamp,
        [parameter(Mandatory = $True,
                Position = 0,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Unit of timestamp.")][ValidateSet("Seconds", "Milliseconds")][String]$Unit = "Milliseconds",
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "Optional Timezone to be used as basis for Timestamp. Default is system Timezone.")][System.TimeZoneInfo]$Timezone = [System.TimeZoneInfo]::Local
    )

    PROCESS {
        $Timestamp = @($Timestamp)
        foreach ($Timestamp in $Timestamp) {
            if ($Unit -eq "Seconds") {
                $Date = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]'1/1/1970').AddSeconds($Timestamp), $Timezone)
            }
            else {
                $Date = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]'1/1/1970').AddMilliseconds($Timestamp), $Timezone)
            }
            Write-Output $Date
        }
    }
}

function ConvertFrom-SgwConfigFile {
    #private
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="StorageGRID Config File")][String]$SgwConfigFile
    )

    Process {
        # TODO: Verify that folder is only readable by current user

        if (!(Test-Path $SgwConfigFile))
        {
            throw "Config file $SgwConfigFile does not exist!"
        }

        Write-Verbose "Reading StorageGRID Configuration from $SgwConfigFile"

        $Content = Get-Content -Path $SgwConfigFile -Raw
        # convert to JSON structure
        # replace all carriage returns
        $Content = $Content -replace "\r",""
        # remove empty lines
        $Content = $Content -replace "(\n$)*", ""
        # remove profile string from profile section
        $Content = $Content -replace "profile ", ""

        # remove keys with empty value
        $Content = $Content -replace "\n\s*([^=\s`"]+)\s*=\s*\n","`n"

        # replace key value pairs with quoted key value pairs and replace = with :
        $Content = $Content -replace "\n\s*([^=\s`"]+)\s*=\s*([^\s\n]*)","`n`"`$1`":`"`$2`","

        # make sure that Profile is a Key Value inside the JSON Object
        $Content = $Content -replace "\[([^\]]+)\]([^\[]+)","{`"ProfileName`":`"`$1`",`$2},`n"

        # remove additional , before a closing curly bracket
        $Content = $Content -replace "\s*,\s*\n?}","}"

        # ensure that the complete output is an array consisting of multiple JSON objects
        $Content = $Content -replace "\A","["
        $Content = $Content -replace "},?\s*\n?\s*\z","}]"

        $Config = ConvertFrom-Json -InputObject $Content
        Write-Output $Config
    }
}

function ConvertTo-SgwConfigFile {
    #private
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Configs to store in config file")][PSCustomObject]$Configs,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="StorageGRID Config File")][String]$SgwConfigFile
    )

    Process {
        # TODO: Verify that folder is only readable by current user

        if (!(Test-Path $SgwConfigFile)) {
            New-Item -Path $SgwConfigFile -ItemType File -Force
        }

        $SgwConfigDirectory = ([System.IO.DirectoryInfo]$SgwConfigFile).Parent.FullName

        # make sure that parent folder is only accessible by current user
        try {
            if ([environment]::OSVersion.Platform -match "win") {
                $Acl = Get-Acl -Path $SgwConfigDirectory
                # remove inheritance
                $Acl.SetAccessRuleProtection($true,$false)
                $AcessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $env:USERNAME,"FullControl",
                    ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow)
                $Acl.AddAccessRule($AcessRule)
                Set-Acl -Path $SgwConfigDirectory -AclRule
            }
            else {
                Invoke-Expression "chmod 700 $SgwConfigDirectory"
                Invoke-Expression "chmod 600 $SgwConfigFile"
            }
        }
        catch {
            Write-Warning "Couldn't restrict access to directory $SgwConfigDirectory"
        }

        Write-Verbose "Writing StorageGRID Configuration to $SgwConfigFile"

        if ($SgwConfigFile -match "credentials$") {
            foreach ($Config in $Configs) {
                $Output += "[$( $Config.ProfileName )]`n"
                $Output += "username = $($Config.username)`n"
                $Output += "password = $($Config.password)`n"
            }
        }
        else {
            foreach ($Config in $Configs) {
                if ($Config.ProfileName -eq "default") {
                    $Output += "[$( $Config.ProfileName )]`n"
                }
                else {
                    $Output += "[profile $( $Config.ProfileName )]`n"
                }
                $Properties = $Config.PSObject.Members | Where-Object { $_.MemberType -eq "NoteProperty" -and $_.Name -ne "ProfileName" -and $_.Value -isnot [PSCustomObject] }
                $Sections = $Config.PSObject.Members | Where-Object { $_.MemberType -eq "NoteProperty" -and $_.Name -ne "ProfileName" -and $_.Value -is [PSCustomObject]}
                foreach ($Property in $Properties) {
                    $Output += "$($Property.Name) = $($Property.Value)`n"
                }
                foreach ($Section in $Sections) {
                    $Output += "$($Section.Name) =`n"
                    $Properties = $Section.Value.PSObject.Members | Where-Object { $_.MemberType -eq "NoteProperty" }
                    foreach ($Property in $Properties) {
                        $Output += "  $($Property.Name) = $($Property.Value)`n"
                    }
                }
            }
        }
        Write-Debug "Output:`n$Output"
        $Output | Out-File -FilePath $SgwConfigFile -NoNewline
    }
}

## function to trigger request to StorageGRID Webscale Server ##

function Invoke-SgwRequest {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $True,
                Position = 0,
                HelpMessage = "Uri")][Uri]$Uri,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "WebSession")][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "HTTP Method")][ValidateSet("Default", "Get", "Head", "Post", "Put", "Delete", "Trace", "Options", "Merge", "Patch")][String]$Method = "Get",
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "Headers")][Hashtable]$Headers,
        [parameter(Mandatory = $False,
                Position = 4,
                HelpMessage = "Body")][Object]$Body,
        [parameter(Mandatory = $False,
                Position = 5,
                HelpMessage = "Content Type")][String]$ContentType = "application/json",
        [parameter(Mandatory = $False,
                Position = 6,
                HelpMessage = "Variable to store session details in")][String]$SessionVariable,
        [parameter(Mandatory = $False,
                Position = 7,
                HelpMessage = "Timeout in seconds")][Int]$TimeoutSec = 60,
        [parameter(Mandatory = $False,
                Position = 8,
                HelpMessage = "Skip certificate checks")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="File to output result to")][System.IO.DirectoryInfo]$OutFile
    )

    Process {
        # if $OutFile is a directory, create a temporary file and save content to temporary file
        # and later rename the file according to the Content-Disposition header or
        $OutPath = $null
        if ($OutFile -and (Test-Path -PathType Container -Path $OutFile)) {
            $OutPath = $OutFile.PSObject.Copy()
            $OutFile = (New-TemporaryFile).ToString()
        }

        try {
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                Write-Verbose "Using Invoke-WebRequest for PowerShell 5 and earlier"
                if ($SkipCertificateCheck.isPresent) {
                    $CurrentCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                }
                if ($Body) {
                    Write-Verbose "Body:`n$Body"
                    if ($SessionVariable) {
                        if ($OutFile) {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType $ContentType -SessionVariable $SessionVariable -OutFile $OutFile -PassThru
                        }
                        else {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType $ContentType -SessionVariable $SessionVariable
                        }
                        $Response | Add-Member  -MemberType NoteProperty -Name $SessionVariable -Value (Get-Variable -Name $SessionVariable -ValueOnly)
                    }
                    else {
                        if ($OutFile) {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType $ContentType -WebSession $WebSession -OutFile $OutFile -PassThru
                        }
                        else {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType $ContentType -WebSession $WebSession
                        }
                    }
                }
                else {
                    if ($SessionVariable) {
                        if ($OutFile) {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec -SessionVariable $SessionVariable -OutFile $OutFile -PassThru
                        }
                        else {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec -SessionVariable $SessionVariable
                        }
                        $Response | Add-Member  -MemberType NoteProperty -Name $SessionVariable -Value (Get-Variable -Name $SessionVariable -ValueOnly) -PassThru
                    }
                    else {
                        if ($OutFile) {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec -WebSession $WebSession -OutFile $OutFile -PassThru
                        }
                        else {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec -WebSession $WebSession
                        }
                    }
                }
                if ($SkipCertificateCheck.isPresent) {
                    [System.Net.ServicePointManager]::CertificatePolicy = $CurrentCertificatePolicy
                }
            }
            else {
                Write-Verbose "Using Invoke-WebRequest for PowerShell 6 and later"
                if ($Body) {
                    Write-Verbose "Body:`n$Body"
                    if ($SessionVariable) {
                        if ($OutFile) {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -SkipCertificateCheck:$SkipCertificateCheck -SkipHeaderValidation -TimeoutSec $TimeoutSec -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType $ContentType -SessionVariable $SessionVariable -OutFile $OutFile -PassThru
                        }
                        else {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -SkipCertificateCheck:$SkipCertificateCheck -SkipHeaderValidation -TimeoutSec $TimeoutSec -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType $ContentType -SessionVariable $SessionVariable
                        }
                        $Response | Add-Member  -MemberType NoteProperty -Name $SessionVariable -Value (Get-Variable -Name $SessionVariable -ValueOnly) -PassThru
                    }
                    else {
                        if ($OutFile) {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -SkipCertificateCheck:$SkipCertificateCheck -SkipHeaderValidation -TimeoutSec $TimeoutSec -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType $ContentType -WebSession $WebSession -OutFile $OutFile -PassThru
                        }
                        else {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -SkipCertificateCheck:$SkipCertificateCheck -SkipHeaderValidation -TimeoutSec $TimeoutSec -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType $ContentType -WebSession $WebSession
                        }
                    }
                }
                else {
                    if ($SessionVariable) {
                        if ($OutFile) {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -SkipCertificateCheck:$SkipCertificateCheck -SkipHeaderValidation -TimeoutSec $TimeoutSec -SessionVariable $SessionVariable -OutFile $OutFile -PassThru
                        }
                        else {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -SkipCertificateCheck:$SkipCertificateCheck -SkipHeaderValidation -TimeoutSec $TimeoutSec -SessionVariable $SessionVariable
                        }
                        $Response | Add-Member  -MemberType NoteProperty -Name $SessionVariable -Value (Get-Variable -Name $SessionVariable -ValueOnly)
                    }
                    else {
                        if ($OutFile) {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -SkipCertificateCheck:$SkipCertificateCheck -SkipHeaderValidation -TimeoutSec $TimeoutSec -WebSession $WebSession -OutFile $OutFile -PassThru
                        }
                        else {
                            $Response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -SkipCertificateCheck:$SkipCertificateCheck -SkipHeaderValidation -TimeoutSec $TimeoutSec -WebSession $WebSession
                        }
                    }
                }
            }

            switch ($Response.Headers.'Content-Type') {
                'application/json' {
                    $Response | Add-Member -MemberType NoteProperty -Name Json -Value (ConvertFrom-Json -InputObject $Response.Content)
                }
            }

            if ($OutPath) {
                if ($Response.Headers.'Content-Disposition' -match "filename") {
                    $FileName = ($Response.Headers.'Content-Disposition' | Select-Object -Last 1) -replace '.*filename="*(.*)"*','$1'
                }
                else {
                    # use last part of Request URI as filename
                    $FileName = $Response.BaseResponse.RequestMessage.RequestUri.Segments | Select-Object -Last 1
                    if ($FileName -eq "/") {
                        $FileName = "index.html"
                    }
                }
                $Destination = Join-Path -Path $OutPath -ChildPath $FileName
                Move-Item -Path $OutFile -Destination $Destination -ErrorAction Stop
                Write-Host "Output written to $Destination"
            }

            return $Response
        }
        catch {
            # TODO: handle errors
            Throw $_
        }
        finally {
            if ($OutFile) {
                Remove-Item -Path $OutFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

### Cmdlets ###

## profile ##

Set-Alias -Name Set-SgwProfile -Value Add-SgwProfile
Set-Alias -Name New-SgwProfile -Value Add-SgwProfile
Set-Alias -Name Update-SgwProfile -Value Add-SgwProfile
Set-Alias -Name Set-SgwCredential -Value Add-SgwProfile
Set-Alias -Name New-SgwCredential -Value Add-SgwProfile
Set-Alias -Name Add-SgwCredential -Value Add-SgwProfile
Set-Alias -Name Update-SgwCredential -Value Add-SgwProfile
<#
    .SYNOPSIS
    Add StorageGRID Profile
    .DESCRIPTION
    Add StorageGRID Profile
    .PARAMETER ProfileName
    StorageGRID Profile to use which contains StorageGRID sredentials and settings
    .PARAMETER ProfileLocation
    StorageGRID Profile location if different than .aws/credentials
    .PARAMETER Name
    The name of the StorageGRID Webscale Management Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.
    .PARAMETER Credential
    A System.Management.Automation.PSCredential object containing the credentials needed to log into the StorageGRID Webscale Management Server.
    .PARAMETER SkipCertificateCheck
    If the StorageGRID Webscale Management Server certificate cannot be verified, the connection will fail. Specify -SkipCertificateCheck to skip the validation of the StorageGRID Webscale Management Server certificate.
    .PARAMETER AccountId
    Account ID of the StorageGRID Webscale tenant to connect to.
    .PARAMETER DisableAutomaticAccessKeyGeneration
    By default StorageGRID automatically generates S3 Access Keys if required to carry out S3 operations. With this switch, automatic S3 Access Key generation will not be done.
    .PARAMETER TemporaryAccessKeyExpirationTime
    Time in seconds until automatically generated temporary S3 Access Keys expire (default 3600 seconds).
    .PARAMETER S3EndpointUrl
    S3 Endpoint URL to be used.
    .PARAMETER SwiftEndpointUrl
    Swift Endpoint URL to be used.
#>
function Global:Add-SgwProfile {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID Profile to use which contains StorageGRID sredentials and settings")][Alias("Profile")][String]$ProfileName="default",
        [parameter(
                Mandatory=$False,
                Position=1,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID Profile location if different than .aws/credentials")][String]$ProfileLocation=$SGW_CREDENTIALS_FILE,
        [parameter(Mandatory = $False,
                Position = 2,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "The name of the StorageGRID Webscale Management Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.")][String]$Name,
        [parameter(Mandatory = $True,
                Position = 3,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "A System.Management.Automation.PSCredential object containing the credentials needed to log into the StorageGRID Webscale Management Server.")][System.Management.Automation.PSCredential]$Credential,
        [parameter(Mandatory = $False,
                Position = 4,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "If the StorageGRID Webscale Management Server certificate cannot be verified, the connection will fail. Specify -SkipCertificateCheck to skip the validation of the StorageGRID Webscale Management Server certificate.")][Alias("Insecure")][Switch]$SkipCertificateCheck,
        [parameter(Position = 5,
                Mandatory = $False,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Account ID of the StorageGRID Webscale tenant to connect to.")][String]$AccountId,
        [parameter(Position = 6,
                Mandatory = $False,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "By default StorageGRID automatically generates S3 Access Keys if required to carry out S3 operations. With this switch, automatic S3 Access Key generation will not be done.")][Switch]$DisableAutomaticAccessKeyGeneration,
        [parameter(Position = 7,
                Mandatory = $False,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Time in seconds until automatically generated temporary S3 Access Keys expire (default 3600 seconds).")][Int]$TemporaryAccessKeyExpirationTime = 3600,
        [parameter(Position = 8,
                Mandatory = $False,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "S3 Endpoint URL to be used.")][System.UriBuilder]$S3EndpointUrl,
        [parameter(Position = 9,
                Mandatory = $False,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Swift Endpoint URL to be used.")][System.UriBuilder]$SwiftEndpointUrl
    )

    Process {
        $ConfigLocation = $ProfileLocation -replace "/[^/]+$", '/config'

        $Credentials = @()
        $Configs = @()

        if ($Credential) {
            try {
                $Credentials = ConvertFrom-SgwConfigFile -SgwConfigFile $ProfileLocation
            }
            catch {
                Write-Verbose "Retrieving credentials from $ProfileLocation failed"
            }

            if (($Credentials | Where-Object { $_.ProfileName -eq $ProfileName })) {
                $CredentialEntry = $Credentials | Where-Object { $_.ProfileName -eq $ProfileName }
            }
            else {
                $CredentialEntry = [PSCustomObject]@{ ProfileName = $ProfileName }
            }

            $CredentialEntry | Add-Member -MemberType NoteProperty -Name username -Value $Credential.UserName -Force
            $CredentialEntry | Add-Member -MemberType NoteProperty -Name password -Value $Credential.GetNetworkCredential().Password -Force

            Write-Debug $CredentialEntry

            $Credentials = (@($Credentials | Where-Object { $_.ProfileName -ne $ProfileName }) + $CredentialEntry) | Where-Object { $_.ProfileName }
            ConvertTo-SgwConfigFile -Config $Credentials -SgwConfigFile $ProfileLocation
        }

        try {
            $Configs = ConvertFrom-SgwConfigFile -SgwConfigFile $ConfigLocation
        }
        catch {
            Write-Verbose "Retrieving config from $ConfigLocation failed"
        }

        $Config = $Configs | Where-Object { $_.ProfileName -eq $ProfileName }
        if (!$Config) {
            $Config = [PSCustomObject]@{ ProfileName = $ProfileName}
        }

        if ($Name) {
            $Config | Add-Member -MemberType NoteProperty -Name name -Value $Name -Force
        }

        if ($AccountId) {
            $Config | Add-Member -MemberType NoteProperty -Name account_id -Value $AccountId -Force
        }

        if ($DisableAutomaticAccessKeyGeneration) {
            $Config | Add-Member -MemberType NoteProperty -Name disable_automatic_access_key_generation -Value $DisableAutomaticAccessKeyGeneration -Force
        }

        if ($TemporaryAccessKeyExpirationTime -and $TemporaryAccessKeyExpirationTime -ne 3600) {
            $Config | Add-Member -MemberType NoteProperty -Name temporary_access_key_expiration_time -Value $TemporaryAccessKeyExpirationTime -Force
        }

        if ($S3EndpointUrl) {
            $S3EndpointUrlString = $S3EndpointUrl -replace "(http://.*:80)",'$1' -replace "(https://.*):443",'$1' -replace "/$",""
            $Config | Add-Member -MemberType NoteProperty -Name s3_endpoint_url -Value $S3EndpointUrlString -Force
        }

        if ($SwiftEndpointUrl) {
            $SwiftEndpointUrlString = $SwiftEndpointUrl -replace "(http://.*:80)",'$1' -replace "(https://.*):443",'$1' -replace "/$",""
            $Config | Add-Member -MemberType NoteProperty -Name swift_endpoint_url -Value $SwiftEndpointUrlString -Force
        }

        if ($SkipCertificateCheck -ne $null) {
            $Config | Add-Member -MemberType NoteProperty -Name skip_certificate_check -Value $SkipCertificateCheck -Force
        }

        $Configs = (@($Configs | Where-Object { $_.ProfileName -ne $ProfileName}) + $Config) | Where-Object { $_.ProfileName }
        ConvertTo-SgwConfigFile -Config $Configs -SgwConfigFile $ConfigLocation
    }
}

Set-Alias -Name Get-SgwCredentials -Value Get-SgwProfiles
<#
    .SYNOPSIS
    Get all StorageGRID profiles
    .DESCRIPTION
    Get the StorageGRID profiles
    .PARAMETER ProfileLocation
    StorageGRID Profile location if different than .aws/credentials
#>
function Global:Get-SgwProfiles {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID Profile location if different than .aws/credentials")][String]$ProfileLocation=$SGW_CREDENTIALS_FILE
    )

    Process {
        if (!$ProfileLocation) {
            $ProfileLocation = $StorageGRID_CREDENTIALS_FILE
        }
        $ConfigLocation = $ProfileLocation -replace "/[^/]+$",'/config'

        if (!(Test-Path $ProfileLocation)) {
            Write-Warning "Profile location $ProfileLocation does not exist!"
            break
        }

        $Credentials = @()
        $Config = @()
        try {
            $Credentials = ConvertFrom-SgwConfigFile -SgwConfigFile $ProfileLocation
        }
        catch {
            Write-Verbose "Retrieving credentials from $ProfileLocation failed"
        }
        try {
            $Configs = ConvertFrom-SgwConfigFile -SgwConfigFile $ConfigLocation
        }
        catch {
            Write-Verbose "Retrieving credentials from $ConfigLocation failed"
        }

        foreach ($Credential in $Credentials) {
            $Config = $Configs | Where-Object { $_.ProfileName -eq $Credential.ProfileName } | Select-Object -First 1
            if (!$Config) {
                $Config = [PSCustomObject]@{ProfileName=$Credential.ProfileName}
                $Configs = @($Configs) + $Config
            }
            if ($Credential.username -and $Credential.password) {
                $Config | Add-Member -MemberType NoteProperty -Name Credential -Value ([PSCredential]::new($Credential.username,($Credential.password | ConvertTo-SecureString -AsPlainText -Force))) -Force
            }
        }

        foreach ($Config in $Configs) {
            $Output = [PSCustomObject]@{ProfileName = $Config.ProfileName;Credential = $Config.Credential}

            if ($Config.Name) {
                $Output | Add-Member -MemberType NoteProperty -Name Name -Value $Config.Name
            }
            else {
                Write-Warning "No StorageGRID name specified for Profile $($Config.ProfileName)"
            }

            if ($Config.account_id) {
                $Output | Add-Member -MemberType NoteProperty -Name AccountId -Value $Config.account_id
            }

            if ($Config.disalble_automatic_access_key_generation) {
                $Output | Add-Member -MemberType NoteProperty -Name DisableAutomaticAccessKeyGeneration -Value ([System.Convert]::ToBoolean($Config.disalble_automatic_access_key_generation))
            }
            else {
                $Output | Add-Member -MemberType NoteProperty -Name DisableAutomaticAccessKeyGeneration -Value $False
            }

            if ($Config.temporary_access_key_expiration_time) {
                $Output | Add-Member -MemberType NoteProperty -Name TemporaryAccessKeyExpirationTime -Value $Config.temporary_access_key_expiration_time
            }
            else {
                $Output | Add-Member -MemberType NoteProperty -Name TemporaryAccessKeyExpirationTime -Value 3600
            }

            if ($Config.s3_endpoint_url) {
                $Output | Add-Member -MemberType NoteProperty -Name S3EndpointUrl -Value $Config.s3_endpoint_url
            }

            if ($Config.swift_endpoint_url) {
                $Output | Add-Member -MemberType NoteProperty -Name SwiftEndpointUrl -Value $Config.swift_endpoint_url
            }

            if ($Config.skip_certificate_check) {
                $Output | Add-Member -MemberType NoteProperty -Name SkipCertificateCheck -Value ([System.Convert]::ToBoolean($Config.skip_certificate_check))
            }
            else {
                $Output | Add-Member -MemberType NoteProperty -Name SkipCertificateCheck -Value $False
            }
            Write-Output $Output
        }
    }
}

Set-Alias -Name Get-SgwCredential -Value Get-SgwProfile
<#
    .SYNOPSIS
    Get StorageGRID Profile
    .DESCRIPTION
    Get StorageGRID Profile
    .PARAMETER ProfileName
    StorageGRID Profile to use which contains StorageGRID sredentials and settings
    .PARAMETER ProfileLocation
    StorageGRID Profile location if different than .aws/credentials
    .PARAMETER Name
    The name of the StorageGRID Webscale Management Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.
    .PARAMETER Credential
    A System.Management.Automation.PSCredential object containing the credentials needed to log into the StorageGRID Webscale Management Server.
    .PARAMETER SkipCertificateCheck
    If the StorageGRID Webscale Management Server certificate cannot be verified, the connection will fail. Specify -SkipCertificateCheck to skip the validation of the StorageGRID Webscale Management Server certificate.
    .PARAMETER AccountId
    Account ID of the StorageGRID Webscale tenant to connect to.
    .PARAMETER DisableAutomaticAccessKeyGeneration
    By default StorageGRID automatically generates S3 Access Keys if required to carry out S3 operations. With this switch, automatic S3 Access Key generation will not be done.
    .PARAMETER TemporaryAccessKeyExpirationTime
    Time in seconds until automatically generated temporary S3 Access Keys expire (default 3600 seconds).
    .PARAMETER S3EndpointUrl
    S3 Endpoint URL to be used.
    .PARAMETER SwiftEndpointUrl
    Swift Endpoint URL to be used.
#>
function Global:Get-SgwProfile {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID Profile to use which contains StorageGRID sredentials and settings")][Alias("Profile")][String]$ProfileName="default",
        [parameter(
                Mandatory=$False,
                Position=1,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID Profile location if different than .aws/credentials")][String]$ProfileLocation=$SGW_CREDENTIALS_FILE,
        [parameter(Mandatory = $False,
                Position = 2,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "The name of the StorageGRID Webscale Management Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.")][String]$Name,
        [parameter(Mandatory = $False,
                Position = 3,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "A System.Management.Automation.PSCredential object containing the credentials needed to log into the StorageGRID Webscale Management Server.")][System.Management.Automation.PSCredential]$Credential,
        [parameter(Mandatory = $False,
                Position = 4,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "If the StorageGRID Webscale Management Server certificate cannot be verified, the connection will fail. Specify -SkipCertificateCheck to skip the validation of the StorageGRID Webscale Management Server certificate.")][Alias("Insecure")][Switch]$SkipCertificateCheck,
        [parameter(Position = 5,
                Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Account ID of the StorageGRID Webscale tenant to connect to.")][String]$AccountId,
        [parameter(Position = 6,
                Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "By default StorageGRID automatically generates S3 Access Keys if required to carry out S3 operations. With this switch, automatic S3 Access Key generation will not be done.")][Switch]$DisableAutomaticAccessKeyGeneration,
        [parameter(Position = 7,
                Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Time in seconds until automatically generated temporary S3 Access Keys expire (default 3600 seconds).")][Int]$TemporaryAccessKeyExpirationTime,
        [parameter(Position = 8,
                Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "S3 Endpoint URL to be used.")][System.UriBuilder]$S3EndpointUrl,
        [parameter(Position = 9,
                Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Swift Endpoint URL to be used.")][System.UriBuilder]$SwiftEndpointUrl
    )

    Begin {
        if (!$Server -and $CurrentSgwServer) {
            $Server = $CurrentSgwServer.PSObject.Copy()
        }
    }

    Process {
        if (!$ProfileName) {
            $ProfileName = "default"
        }

        $Configs = Get-SgwProfiles

        $Config = $Configs | Where-Object { $_.ProfileName -eq $ProfileName }

        if (!$Config) {
            $Config = [PSCustomObject]@{ProfileName = $ProfileName;
                Name = $Name;
                Credential = $Credential;
                SkipCertificateCheck = $SkipCertificateCheck;
                AccountId = $AccountId;
                DisableAutomaticAccessKeyGeneration = $DisableAutomaticAccessKeyGeneration;
                TemporaryAccessKeyExpirationTime = $TemporaryAccessKeyExpirationTime;
                S3EndpointUrl = $S3EndpointUrl;
                SwiftEndpointUrl = $SwiftEndpointUrl}
        }

        if ($Name) {
            $Config.Name = $Name
        }

        if ($Credential) {
            $Config.Credential = $Credential
        }

        if ($SkipCertificateCheck -ne $null) {
            $Config.SkipCertificateCheck = $SkipCertificateCheck
        }
        elseif (!$Config.SkipCertificateCheck) {
            $Config.SkipCertificateCheck = $False
        }

        if ($AccountId) {
            $Config.AccountId = $AccountId
        }

        if ($DisableAutomaticAccessKeyGeneration) {
            $Config.DisableAutomaticAccessKeyGeneration = $DisableAutomaticAccessKeyGeneration
        }
        elseif (!$Config.DisableAutomaticAccessKeyGeneration) {
            $Config.DisableAutomaticAccessKeyGeneration = $False
        }

        if ($TemporaryAccessKeyExpirationTime) {
            $Config.TemporaryAccessKeyExpirationTime = $TemporaryAccessKeyExpirationTime
        }
        elseif (!$Config.TemporaryAccessKeyExpirationTime) {
            $Config.TemporaryAccessKeyExpirationTime = 3600
        }

        if ($S3EndpointUrl) {
            $Config.S3EndpointUrl = $S3EndpointUrl
        }

        if ($SwiftEndpointUrl) {
            $Config.SwiftEndpointUrl = $SwiftEndpointUrl
        }

        Write-Output $Config
    }
}

Set-Alias -Name Remove-SgwCredential -Value Remove-SgwProfile
<#
    .SYNOPSIS
    Remove StorageGRID Profile
    .DESCRIPTION
    Remove StorageGRID Profile
    .PARAMETER ProfileName
    StorageGRID Profile to remove which contains StorageGRID sredentials and settings
    .PARAMETER ProfileLocation
    StorageGRID Profile location if different than .aws/credentials
#>
function Global:Remove-SgwProfile {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="StorageGRID Profile where config should be removed")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory=$False,
                Position=1,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID Profile location if different than .aws/credentials")][String]$ProfileLocation=$SGW_CREDENTIALS_FILE
    )

    Process {
        $ConfigLocation = $ProfileLocation -replace "/[^/]+$",'/config'

        $Credentials = ConvertFrom-SgwConfigFile -SgwConfigFile $ProfileLocation
        $Credentials = $Credentials | Where-Object { $_.ProfileName -ne $ProfileName }
        ConvertTo-SgwConfigFile -Config $Credentials -SgwConfigFile $ProfileLocation

        $Configs = ConvertFrom-SgwConfigFile -SgwConfigFile $ConfigLocation
        $Configs = $Configs | Where-Object { $_.ProfileName -ne $ProfileName }
        ConvertTo-SgwConfigFile -Config $Configs -SgwConfigFile $ConfigLocation
    }
}

## accounts ##

# complete as of API 2.2

<#
    .SYNOPSIS
    Retrieve all StorageGRID Webscale Accounts
    .DESCRIPTION
    Retrieve all StorageGRID Webscale Accounts
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Limit
    Maximum number of results.
    .PARAMETER Marker
    Pagination offset (value is Account's id).
    .PARAMETER IncludeMarker
    If set, the marker element is also returned.
    .PARAMETER Order
    Pagination order (desc requires marker).
    .PARAMETER Capabilities
    Comma separated list of capabilities of the accounts to return. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).
#>
function Global:Get-SgwAccounts {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "Maximum number of results.")][Int]$Limit = 0,
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "Pagination offset (value is Account's id).")][String]$Marker,
        [parameter(Mandatory = $False,
                Position = 4,
                HelpMessage = "If set, the marker element is also returned.")][Switch]$IncludeMarker,
        [parameter(Mandatory = $False,
                Position = 5,
                HelpMessage = "Pagination order (desc requires marker).")][ValidateSet("asc", "desc")][String]$Order = "asc",
        [parameter(Mandatory = $False,
                Position = 6,
                HelpMessage = "Comma separated list of capabilities of the accounts to return. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).")][ValidateSet("swift", "s3", "management")][String[]]$Capabilities
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
        if ($Marker) {
            $Query += "&marker=$Marker"
        }
        if ($IncludeMarker) {
            $Query += "&includeMarker=true"
        }
        if ($Order) {
            $Query += "&order=$Order"
        }

        $Uri += $Query

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Write-Error "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $( $responseBody.message )"
            return
        }

        $Accounts = $Response.Json.data

        if ($Capabilities) {
            $Accounts = $Accounts | Where-Object { ($_.capabilities -join ",") -match ($Capabilities -join "|") }
        }

        foreach ($Account in $Accounts) {
            $Account | Add-Member -MemberType AliasProperty -Name accountId -Value id
            $Account | Add-Member -MemberType AliasProperty -Name tenant -Value name
            $Account | Add-Member -MemberType NoteProperty -Name tenantPortal -Value "https://$( $Server.Name )/?accountId=$( $Account.id )"
            $Account | Add-Member -MemberType ScriptProperty -Name useAccountIdentitySource -Value { $this.Policy.useAccountIdentitySource }
            $Account | Add-Member -MemberType ScriptProperty -Name allowPlatformServices -Value { $this.Policy.allowPlatformServices }
            $Account | Add-Member -MemberType ScriptProperty -Name quota -Value { $this.Policy.quotaObjectBytes }
        }

        Write-Output $Accounts

        if ($Limit -eq 0 -and $Response.Json.data.count -eq 25) {
            if ($Capabilities) {
                Get-SgwAccounts -Server $Server -Limit $Limit -Marker ($Response.Json.data | select -last 1 -ExpandProperty id) -IncludeMarker:$IncludeMarker -Order $Order -Capabilities $Capabilities
            }
            else {
                Get-SgwAccounts -Server $Server -Limit $Limit -Marker ($Response.Json.data | select -last 1 -ExpandProperty id) -IncludeMarker:$IncludeMarker -Order $Order
            }
        }
    }
}

<#
    .SYNOPSIS
    Create a StorageGRID Webscale Account
    .DESCRIPTION
    Create a StorageGRID Webscale Account
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    Name of the StorageGRID Webscale Account to be created.
    .PARAMETER Capabilities
    Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management).
    .PARAMETER UseAccountIdentitySource
    Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management).
    .PARAMETER AllowPlatformServices
    Allow platform services to be used (default: true - supported since StorageGRID 11.0).
    .PARAMETER Quota
    Quota for tenant in bytes.
    .PARAMETER Password
    Tenant root password (must be at least 8 characters).
    .EXAMPLE
    Create new account with S3 and Management capabilities

    New-SgwAccount -Name MyAccount -Capabilities s3,management -Password t9eM66Y2
    .EXAMPLE
    Create new account with Swift and Management capabilities and do not allow own Identity Federation configuration

    New-SgwAccount -Name MyAccount -Capabilities swift,management -UseAccountIdentitySource $false -Password t9eM66Y2
    .EXAMPLE
    Create new account with S3 and Management capabilities and set Quota

    New-SgwAccount -Name MyAccount -Capabilities swift,management -UseAccountIdentitySource $false -Quota 1TB -Password t9eM66Y2
#>
function Global:New-SgwAccount {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "Name of the StorageGRID Webscale Account to be created.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Name,
        [parameter(
                Mandatory = $True,
                Position = 3,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management).")][ValidateSet("swift", "s3", "management")][String[]]$Capabilities,
        [parameter(
                Mandatory = $False,
                Position = 4,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Use account identity source (default: true - supported since StorageGRID 10.4).")][Boolean]$UseAccountIdentitySource = $true,
        [parameter(
                Mandatory = $False,
                Position = 5,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Allow platform services to be used (default: true - supported since StorageGRID 11.0).")][Boolean]$AllowPlatformServices = $false,
        [parameter(
                Mandatory = $False,
                Position = 6,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Quota for tenant in bytes.")][Alias("QuotaObjectBytes")][Long]$Quota,
        [parameter(
                Mandatory = $False,
                Position = 7,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Policy object containing information on identity source, platform service and quota")][PSCustomObject]$Policy = @{ },
        [parameter(
                Mandatory = $False,
                Position = 8,
                HelpMessage = "Tenant root password (must be at least 8 characters).")][ValidateLength(8, 256)][String]$Password
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -ge 2 -and !$Password) {
            Throw "Password required"
        }
        if ($Server.APIVersion -lt 2 -and ($Quota -or $Password)) {
            Write-Warning "Quota and password will be ignored in API Version $( $Server.APIVersion )"
        }
        if ($Server.APIVersion -lt 2 -and $UseAccountIdentitySource.isPresent) {
            Write-Warning "Use Account Services is only Supported from StorageGRID 10.4"
        }
        if ($Server.APIVersion -lt 2.1 -and $AllowPlatformServices.isPresent) {
            Write-Warning "Use Account Services is only Supported from StorageGRID 11.0"
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
        if ($Password) {
            if ($Password.length -lt 8) {
                Throw "Password does not meet minimum length requirement of 8 characters"
            }
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/accounts"
        $Method = "POST"

        $Body = @{ }
        $Body.name = $Name
        $Body.capabilities = $Capabilities

        if ($Server.APIVersion -ge 2) {
            $Body.password = $Password
            $Body.policy = $Policy
            $Body.policy.useAccountIdentitySource = $UseAccountIdentitySource
            if ($Server.APIVersion -ge 2.1) {
                $Body.policy.allowPlatformServices = $AllowPlatformServices
            }
            if ($Quota) {
                $Body.policy.quotaObjectBytes = $Quota
            }
        }

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Account = $Response.Json.data

        $Account | Add-Member -MemberType AliasProperty -Name accountId -Value id
        $Account | Add-Member -MemberType AliasProperty -Name tenant -Value name
        $Account | Add-Member -MemberType NoteProperty -Name tenantPortal -Value "https://$( $Server.Name )/?accountId=$( $Account.id )"
        $Account | Add-Member -MemberType ScriptProperty -Name useAccountIdentitySource -Value { $this.Policy.useAccountIdentitySource }
        $Account | Add-Member -MemberType ScriptProperty -Name allowPlatformServices -Value { $this.Policy.allowPlatformServices }
        $Account | Add-Member -MemberType ScriptProperty -Name quota -Value { $this.Policy.quotaObjectBytes }

        Write-Output $Account
    }
}

<#
    .SYNOPSIS
    Delete a StorageGRID Webscale Account
    .DESCRIPTION
    Delete a StorageGRID Webscale Account
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    ID of a StorageGRID Webscale Account to delete.
#>
function Global:Remove-SgwAccount {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "ID of a StorageGRID Webscale Account to delete.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("AccountId")][String]$Id
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/accounts/$id"
        $Method = "DELETE"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
            Write-Verbose "Successfully deleted account with ID $id"
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }
    }
}

<#
    .SYNOPSIS
    Retrieve a StorageGRID Webscale Account
    .DESCRIPTION
    Retrieve a StorageGRID Webscale Account
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    ID of a StorageGRID Webscale Account to get information for.
    .PARAMETER Name
    Name of a StorageGRID Webscale Account to get information for.
#>
function Global:Get-SgwAccount {
    [CmdletBinding(DefaultParameterSetName = "id")]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                ParameterSetName = "id",
                HelpMessage = "ID of a StorageGRID Webscale Account to get information for.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("AccountId")][String]$Id,
        [parameter(
                Mandatory = $True,
                Position = 2,
                ParameterSetName = "name",
                HelpMessage = "Name of a StorageGRID Webscale Account to get information for.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        if ($Name) {
            # this is a convenience method for retrieving an account by name
            $Account = Get-SgwAccounts | ? { $_.Name -eq $Name }
            Write-Output $Account
        }
        else {
            $Uri = $Server.BaseURI + "/grid/accounts/$AccountId"
            $Method = "GET"

            try {
                $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
            }
            catch {
                $ResponseBody = ParseErrorForResponseBody $_
                Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
            }

            $Account = $Response.Json.data
            $Account | Add-Member -MemberType AliasProperty -Name accountId -Value id
            $Account | Add-Member -MemberType AliasProperty -Name tenant -Value name
            $Account | Add-Member -MemberType NoteProperty -Name tenantPortal -Value "https://$( $Server.Name )/?accountId=$( $Account.AccountId )"
            $Account | Add-Member -MemberType ScriptProperty -Name useAccountIdentitySource -Value { $this.Policy.useAccountIdentitySource }
            $Account | Add-Member -MemberType ScriptProperty -Name allowPlatformServices -Value { $this.Policy.allowPlatformServices }
            $Account | Add-Member -MemberType ScriptProperty -Name quota -Value { $this.Policy.quotaObjectBytes }

            Write-Output $Account
        }
    }
}

<#
    .SYNOPSIS
    Update a StorageGRID Webscale Account
    .DESCRIPTION
    Update a StorageGRID Webscale Account
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    ID of a StorageGRID Webscale Account to update.
    .PARAMETER Capabilities
    Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).
    .PARAMETER Name
    New name of the StorageGRID Webscale Account.
    .PARAMETER UseAccountIdentitySource
    Use account identity source (supported since StorageGRID 10.4).
    .PARAMETER AllowPlatformServices
    Allow platform services to be used (supported since StorageGRID 11.0).
    .PARAMETER Quota
    Quota for tenant in bytes.
#>
function Global:Update-SgwAccount {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "ID of a StorageGRID Webscale Account to update.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).")][String[]]$Capabilities,
        [parameter(
                Mandatory = $False,
                Position = 4,
                HelpMessage = "New name of the StorageGRID Webscale Account.")][String]$Name,
        [parameter(
                Mandatory = $False,
                Position = 5,
                HelpMessage = "Use account identity source (supported since StorageGRID 10.4).")][Boolean]$UseAccountIdentitySource = $true,
        [parameter(
                Mandatory = $False,
                Position = 6,
                HelpMessage = "Allow platform services to be used (supported since StorageGRID 11.0).")][Boolean]$AllowPlatformServices = $false,
        [parameter(
                Mandatory = $False,
                Position = 7,
                HelpMessage = "Quota for tenant in bytes.")][Long]$Quota
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }

        if ($Server.APIVersion -lt 2 -and ($Quota -or $Password)) {
            Write-Warning "Quota and password will be ignored in API Version $( $Server.APIVersion )"
        }
        if ($Server.APIVersion -lt 2 -and $UseAccountIdentitySource.isPresent) {
            Write-Warning "Use Account Services is only Supported from StorageGRID 10.4"
        }
        if ($Server.APIVersion -lt 2.1 -and $AllowPlatformServices.isPresent) {
            Write-Warning "Use Account Services is only Supported from StorageGRID 11.0"
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/accounts/$id"
        $Method = "PATCH"

        $Body = @{ }
        if ($Name) {
            $Body.name = $Name
        }
        if ($Capabilities) {
            $Body.capabilities = $Capabilities
        }

        if ($Server.APIVersion -ge 2) {
            $Body.policy = @{ "useAccountIdentitySource" = $UseAccountIdentitySource }
            if ($Server.APIVersion -ge 2.1) {
                $Body.policy["allowPlatformServices"] = $AllowPlatformServices
            }
            if ($Quota) {
                $Body.policy.quotaObjectBytes = $Quota
            }
        }

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Account = $Response.Json.data
        $Account | Add-Member -MemberType AliasProperty -Name accountId -Value id
        $Account | Add-Member -MemberType AliasProperty -Name tenant -Value name
        $Account | Add-Member -MemberType NoteProperty -Name tenantPortal -Value "https://$( $Server.Name )/?accountId=$( $Account.id )"
        $Account | Add-Member -MemberType ScriptProperty -Name useAccountIdentitySource -Value { $this.Policy.useAccountIdentitySource }
        $Account | Add-Member -MemberType ScriptProperty -Name allowPlatformServices -Value { $this.Policy.allowPlatformServices }
        $Account | Add-Member -MemberType ScriptProperty -Name quota -Value { $this.Policy.quotaObjectBytes }

        Write-Output $Account
    }
}

<#
    .SYNOPSIS
    Replace a StorageGRID Webscale Account
    .DESCRIPTION
    Replace a StorageGRID Webscale Account
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    ID of a StorageGRID Webscale Account to replace.
    .PARAMETER Capabilities
    Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).
    .PARAMETER Name
    New name of the StorageGRID Webscale Account.
    .PARAMETER UseAccountIdentitySource
    Use account identity source (supported since StorageGRID 10.4).
    .PARAMETER AllowPlatformServices
    Allow platform services to be used (supported since StorageGRID 11.0).
    .PARAMETER Quota
    Quota for tenant in bytes.
#>
function Global:Replace-SgwAccount {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "ID of a StorageGRID Webscale Account to replace.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "Comma separated list of capabilities of the account. Can be swift, S3 and management (e.g. swift,s3 or s3,management ...).")][String[]]$Capabilities,
        [parameter(
                Mandatory = $False,
                Position = 4,
                HelpMessage = "New name of the StorageGRID Webscale Account.")][String]$Name,
        [parameter(
                Mandatory = $False,
                Position = 5,
                HelpMessage = "Use account identity source (supported since StorageGRID 10.4).")][Boolean]$UseAccountIdentitySource = $true,
        [parameter(
                Mandatory = $False,
                Position = 6,
                HelpMessage = "Allow platform services to be used (supported since StorageGRID 11.0).")][Boolean]$AllowPlatformServices = $false,
        [parameter(
                Mandatory = $False,
                Position = 7,
                HelpMessage = "Quota for tenant in bytes.")][Long]$Quota
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }

        if ($Server.APIVersion -lt 2 -and ($Quota -or $Password)) {
            Write-Warning "Quota and password will be ignored in API Version $( $Server.APIVersion )"
        }
        if ($Server.APIVersion -lt 2 -and $UseAccountIdentitySource.isPresent) {
            Write-Warning "Use Account Services is only Supported from StorageGRID 10.4"
        }
        if ($Server.APIVersion -lt 2.1 -and $AllowPlatformServices.isPresent) {
            Write-Warning "Use Account Services is only Supported from StorageGRID 11.0"
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/accounts/$id"
        $Method = "PUT"

        $Body = @{ }
        if ($Name) {
            $Body.name = $Name
        }
        if ($Capabilities) {
            $Body.capabilities = $Capabilities
        }

        if ($Server.APIVersion -ge 2) {
            $Body.policy = @{ "useAccountIdentitySource" = $UseAccountIdentitySource }
            if ($Server.APIVersion -ge 2.1) {
                $Body.policy["allowPlatformServices"] = $AllowPlatformServices
            }
            if ($Quota) {
                $Body.policy.quotaObjectBytes = $Quota
            }
        }

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Account = $Response.Json.data
        $Account | Add-Member -MemberType AliasProperty -Name accountId -Value id
        $Account | Add-Member -MemberType AliasProperty -Name tenant -Value name
        $Account | Add-Member -MemberType NoteProperty -Name tenantPortal -Value "https://$( $Server.Name )/?accountId=$( $Account.id )"
        $Account | Add-Member -MemberType ScriptProperty -Name useAccountIdentitySource -Value { $this.Policy.useAccountIdentitySource }
        $Account | Add-Member -MemberType ScriptProperty -Name allowPlatformServices -Value { $this.Policy.allowPlatformServices }
        $Account | Add-Member -MemberType ScriptProperty -Name quota -Value { $this.Policy.quotaObjectBytes }

        Write-Output $Account
    }
}

<#
    .SYNOPSIS
    Change Swift Admin Password for StorageGRID Webscale Account
    .DESCRIPTION
    Change Swift Admin Password for StorageGRID Webscale Account
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    ID of a StorageGRID Webscale Account to update.
    .PARAMETER OldPassword
    Old Password.
    .PARAMETER NewPassword
    New Password.
#>
function Global:Update-SgwSwiftAdminPassword {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "ID of a StorageGRID Webscale Account to update.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id,
        [parameter(
                Mandatory = $True,
                Position = 3,
                HelpMessage = "Old Password.")][String]$OldPassword,
        [parameter(
                Mandatory = $True,
                Position = 4,
                HelpMessage = "New Password.")][String]$NewPassword
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -gt 1) {
            Throw "This Cmdlet is only supported with API Version 1.0. Use the new Update-SgwPassword Cmdlet instead!"
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/accounts/$id/swift-admin-password"
        $Method = "POST"

        $Body = ConvertTo-Json -InputObject @{password = $NewPassword;currentPassword = $OldPassword}

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Changes the root user password for the Storage Tenant Account
    .DESCRIPTION
    Changes the root user password for the Storage Tenant Account
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    ID of a StorageGRID Webscale Account to update.
    .PARAMETER OldPassword
    Old Password.
    .PARAMETER NewPassword
    CNew Password.
#>
function Global:Update-SgwPassword {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "ID of a StorageGRID Webscale Account to update.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id,
        [parameter(
                Mandatory = $True,
                Position = 3,
                HelpMessage = "Old Password.")][String]$OldPassword,
        [parameter(
                Mandatory = $True,
                Position = 4,
                HelpMessage = "New Password.")][String]$NewPassword
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2) {
            Write-Error "This Cmdlet is only supported with API Version 2.0 and later. Use the old Update-SgwSwiftAdminPassword Cmdlet instead!"
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/accounts/$id/change-password"
        $Method = "POST"

        $Body = ConvertTo-Json -InputObject @{password = $NewPassword;currentPassword = $OldPassword}

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieve StorageGRID Webscale Account Usage Report
    .DESCRIPTION
    Retrieve StorageGRID Webscale Account Usage Report
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    ID of a StorageGRID Webscale Account to get usage information for.
#>
function Global:Get-SgwAccountUsage {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory = $False,
                Position = 2,
                HelpMessage = "ID of a StorageGRID Webscale Account to get usage information for.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$id
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
            return
        }

        $Response.Json.data | Add-Member -MemberType NoteProperty -Name id -Value $Id

        Write-Output $Response.Json.data
    }
}

## alarms ##

# complete as of API 2.2

<#
    .SYNOPSIS
    Retrieve all StorageGRID Webscale Alarms
    .DESCRIPTION
    Retrieve all StorageGRID Webscale Alarms
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER IncludeAcknowledged
    If set, acknowledged alarms are also returned.
    .PARAMETER Limit
    Maximum number of results.
#>
function Global:Get-SgwAlarms {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "If set, acknowledged alarms are also returned.")][Switch]$IncludeAcknowledged,
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "Maximum number of results.")][int]$Limit
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Uri += "$( $Separator )includeAcknowledged=true"
            $Separator = "&"
        }
        if ($limit) {
            $Uri += "$( $Separator )limit=$limit"
        }

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## audit ##

# complete as of API 2.2

<#
    .SYNOPSIS
    Gets the audit configuration
    .DESCRIPTION
    Gets the audit configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwAudit {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + '/grid/audit'
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Audit = [PSCustomObject]@{
            LevelSystem = $Response.Json.data.levels.system;
            LevelStorage = $Response.Json.data.levels.storage;
            LevelProtocol = $Response.Json.data.levels.protocol;
            LevelManagement = $Response.Json.data.levels.management;
            LoggedHeaders = $Response.Json.data.loggedHeaders
        }

        Write-Output $Audit
    }
}

<#
    .SYNOPSIS
    Replace the audit configuration
    .DESCRIPTION
    Replace the audit configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER LevelSystem
    Audit log level for system.
    .PARAMETER LevelStorage
    Audit log level for storage.
    .PARAMETER LevelProtocol
    Audit log level for protocol.
    .PARAMETER LevelManagement
    Audit log level for management.
    .PARAMETER LoggedHeaders
    Logged headers.
#>
function Global:Replace-SgwAudit {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Audit log level for system.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][ValidateSet("off","error","normal","debug")][String]$LevelSystem,
        [parameter(Mandatory = $True,
                Position = 3,
                HelpMessage = "Audit log level for storage.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][ValidateSet("off","error","normal","debug")][String]$LevelStorage,
        [parameter(Mandatory = $True,
                Position = 4,
                HelpMessage = "Audit log level for protocol.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][ValidateSet("off","error","normal","debug")][String]$LevelProtocol,
        [parameter(Mandatory = $True,
                Position = 5,
                HelpMessage = "Audit log level for management.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][ValidateSet("off","error","normal","debug")][String]$LevelManagement,
        [parameter(Mandatory = $False,
                Position = 6,
                HelpMessage = "Logged headers.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String[]]$LoggedHeaders
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + '/grid/audit'
        $Method = "PUT"

        $Body = @{}
        $Body.levels = @{}
        $Body.levels.system = $LevelSystem
        $Body.levels.storage = $LevelStorage
        $Body.levels.protocol = $LevelProtocol
        $Body.levels.management = $LevelManagement
        $Body.loggedHeaders = $LoggedHeaders

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Body $Body -ContentType "application/json" -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Audit = [PSCustomObject]@{
            LevelSystem = $Response.Json.data.levels.system;
            LevelStorage = $Response.Json.data.levels.storage;
            LevelProtocol = $Response.Json.data.levels.protocol;
            LevelManagement = $Response.Json.data.levels.management;
            LoggedHeaders = $Response.Json.data.loggedHeaders
        }

        Write-Output $Audit
    }
}

## auth ##

# complete as of API 2.2

<#
    .SYNOPSIS
    Connect to StorageGRID Webscale Management Server
    .DESCRIPTION
    Connect to StorageGRID Webscale Management Server
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    The name of the StorageGRID Webscale Management Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.
    .PARAMETER Credential
    A System.Management.Automation.PSCredential object containing the credentials needed to log into the StorageGRID Webscale Management Server.
    .PARAMETER SkipCertificateCheck
    If the StorageGRID Webscale Management Server certificate cannot be verified, the connection will fail. Specify -SkipCertificateCheck to skip the validation of the StorageGRID Webscale Management Server certificate.
    .PARAMETER Transient
    If set the global variable `$CurrentOciServer will not be set and the Server must be explicitly specified for all Cmdlets.
    .PARAMETER AccountId
    Account ID of the StorageGRID Webscale tenant to connect to.
    .PARAMETER DisableAutomaticAccessKeyGeneration
    By default StorageGRID automatically generates S3 Access Keys if required to carry out S3 operations. With this switch, automatic S3 Access Key generation will not be done.
    .PARAMETER TemporaryAccessKeyExpirationTime
    Time in seconds until automatically generated temporary S3 Access Keys expire.
    .PARAMETER S3EndpointUrl
    S3 Endpoint URL to be used.
    .PARAMETER SwiftEndpointUrl
    Swift Endpoint URL to be used.
    .EXAMPLE
    Minimum required information to connect with a StorageGRID Webscale Admin Node

    $Name = "admin-node.example.org"
    $Credential = Get-Credential
    Connect-SgwServer -Name $Name -Credential $Credential
    .EXAMPLE
    Skip certificate validation

    $Name = "admin-node.example.org"
    $Credential = Get-Credential
    Connect-SgwServer -Name $Name -Credential $Credential -SkipCertificateCheck
    .EXAMPLE
    Do not store server in global variable

    $Name = "admin-node.example.org"
    $Credential = Get-Credential"
    Connect-SgwServer -Name $Name -Credential $Credential -Transient
    .EXAMPLE
    Connect as StorageGRID Webscale tenant

    $Name = "admin-node.example.org"
    $Credential = Get-Credential
    $AccountId = "12345678901234567890"
    Connect-SgwServer -Name $Name -Credential $Credential -AccountId
#>
function global:Connect-SgwServer {
    [CmdletBinding(DefaultParameterSetName="profile")]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                ParameterSetName="profile",
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName="default",
        [parameter(
                Mandatory = $True,
                Position = 1,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                ParameterSetName="name",
                HelpMessage = "The name of the StorageGRID Webscale Management Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.")][String]$Name,
        [parameter(
                Mandatory = $True,
                Position = 2,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                ParameterSetName="name",
                HelpMessage = "A System.Management.Automation.PSCredential object containing the credentials needed to log into the StorageGRID Webscale Management Server.")][System.Management.Automation.PSCredential]$Credential,
        [parameter(
                Mandatory = $False,
                Position = 3,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "If the StorageGRID Webscale Management Server certificate cannot be verified, the connection will fail. Specify -SkipCertificateCheck to skip the validation of the StorageGRID Webscale Management Server certificate.")][Alias("Insecure")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory = $False,
                Position = 4,
                HelpMessage = "Specify -Transient to not set the global variable `$CurrentOciServer.")][Switch]$Transient,
        [parameter(
                Mandatory = $False,
                Position = 5,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Account ID of the StorageGRID Webscale tenant to connect to.")][String]$AccountId,
        [parameter(
                Mandatory = $False,
                Position = 6,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "By default StorageGRID automatically generates S3 Access Keys if required to carry out S3 operations. With this switch, automatic S3 Access Key generation will not be done.")][Switch]$DisableAutomaticAccessKeyGeneration,
        [parameter(
                Mandatory = $False,
                Position = 7,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Time in seconds until automatically generated temporary S3 Access Keys expire (default 3600 seconds).")][Int]$TemporaryAccessKeyExpirationTime = 3600,
        [parameter(
                Mandatory = $False,
                Position = 8,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "S3 Endpoint URL to be used.")][System.UriBuilder]$S3EndpointUrl,
        [parameter(
                Mandatory = $False,
                Position = 9,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Swift Endpoint URL to be used.")][System.UriBuilder]$SwiftEndpointUrl
    )

    Process {
        if (!$Name) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found and no name specified."
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient:$Transient
            return $Server
        }

        $Server = [PSCustomObject]@{
            SkipCertificateCheck = $SkipCertificateCheck.IsPresent;
            Name = $Name;
            User = $Credential.UserName;
            Credential = $Credential;
            BaseUri = "https://$Name/api/v2";
            Session = New-Object -TypeName Microsoft.PowerShell.Commands.WebRequestSession
            Headers = New-Object -TypeName Hashtable
            ApiVersion = 0;
            SupportedApiVersions = @();
            S3EndpointUrl = $null;
            SwiftEndpointUrl = $null;
            DisableAutomaticAccessKeyGeneration = $DisableAutomaticAccessKeyGeneration.isPresent;
            TemporaryAccessKeyExpirationTime = $TemporaryAccessKeyExpirationTime;
            AccessKeyStore = @{ };
            AccountId = "";
            TenantPortal = ""
        }

        if ([environment]::OSVersion.Platform -match "Win") {
            # check if proxy is used
            $ProxyRegistry = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $ProxySettings = Get-ItemProperty -Path $ProxyRegistry
            if ($ProxySettings.ProxyEnable) {
                Write-Warning "Proxy Server $( $ProxySettings.ProxyServer ) configured in Internet Explorer may be used to connect to the OCI server!"
            }
            if ($ProxySettings.AutoConfigURL) {
                Write-Warning "Proxy Server defined in automatic proxy configuration script $( $ProxySettings.AutoConfigURL ) configured in Internet Explorer may be used to connect to the OCI server!"
            }
        }

        $Body = @{ }
        $Body.username = $Credential.UserName
        $Body.password = $Credential.GetNetworkCredential().Password
        $Body.cookie = $True
        $Body.csrfToken = $True

        if ($AccountId) {
            $Body.accountId = $AccountId
            $Server.AccountId = $AccountId
            $Server.TenantPortal = "https://$( $Server.Name )/?accountId=$( $Account.id )"
        }

        $Body = ConvertTo-Json -InputObject $Body

        $APIVersion = (Get-SgwVersion -Server $Server -ErrorAction Stop | Sort-Object | select -Last 1) -replace "\..*", ""

        if (!$APIVersion) {
            Throw "API Version could not be retrieved via https://$Name/api/versions"
        }

        $Server.BaseUri = "https://$Name/api/v2"

        Try {
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                $CurrentCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                try {
                    $Response = Invoke-RestMethod -SessionVariable "Session" -Method POST -Uri "$( $Server.BaseUri )/authorize" -TimeoutSec 10 -ContentType "application/json" -Body $Body
                }
                catch {
                    Throw
                }
                finally {
                    [System.Net.ServicePointManager]::CertificatePolicy = $CurrentCertificatePolicy
                }
            }
            else {
                $Response = Invoke-RestMethod -SessionVariable "Session" -Method POST -Uri "$( $Server.BaseUri )/authorize" -TimeoutSec 10 -ContentType "application/json" -Body $Body -SkipCertificateCheck:$Server.SkipCertificateCheck
            }
        }
        Catch {
            $ResponseBody = ParseErrorForResponseBody $_
            if ($_.Exception.Message -match "Unauthorized") {
                Write-Error "Authorization for $BaseURI/authorize with user $( $Credential.UserName ) failed"
                return
            }
            elseif ($_.Exception.Message -match "trust relationship") {
                Write-Error $_.Exception.Message
                Write-Information "Certificate of the server is not trusted. Use -SkipCertificateCheck switch if you want to skip certificate verification."
            }
            else {
                Write-Error "Login to $BaseURI/authorize failed via HTTPS protocol. Exception message: $( $_.Exception.Message )`n $ResponseBody"
                return
            }
        }

        if ($Response.status -ne "success") {
            Throw "Authorization failed with status $( $Response.status )"
        }

        $Server.Headers["Authorization"] = "Bearer $( $Response.data )"

        $Server.Session = $Session
        if (($Server.Session.Cookies.GetCookies($Server.BaseUri) | ? { $_.Name -match "CsrfToken" })) {
            $XCsrfToken = $Server.Session.Cookies.GetCookies($Server.BaseUri) | ? { $_.Name -match "CsrfToken" } | select -ExpandProperty Value
            $Server.Headers["X-Csrf-Token"] = $XCsrfToken
        }

        $Server.ApiVersion = $Response.apiVersion

        $SupportedApiVersions = @(Get-SgwVersions -Server $Server)
        if (!$SupportedApiVersions.Contains(1)) {
            Write-Warning "API Version 1 not supported. API Version 1 is required to autogenerate S3 credentials for Grid Administrators. If you want to run the S3 Cmdlets as Grid Administrator and let the Cmdlets autogenerate S3 credentials, then enable API Version 1 with`nUpdate-SgwConfigManagement -MinApiVersion 1"
        }
        $Server.SupportedApiVersions = $SupportedApiVersions

        if ($S3EndpointUrl) {
            $Server.S3EndpointUrl = $S3EndpointUrl
        }

        if ($SwiftEndpointUrl) {
            $Server.SwiftEndpointUrl = $SwiftEndpointUrl
        }

        if (!$AccountId -and !$Server.S3EndpointUrl) {
            Write-Verbose "Trying to identify S3 and Swift Endpoints"
            # check endpoint urls and try StorageGRID default ports 8082 and 18082 for S3 and 8083 and 18083 for Swift
            $EndpointDomainNames = Get-SgwEndpointDomainNames -Server $Server | % { @("https://$_", "https://${_}:8082", "https://${_}:18082", "https://${_}:8083", "https://${_}:18083") }
            foreach ($EndpointDomainName in $EndpointDomainNames) {
                Write-Verbose "Endpoint domain name: $EndpointDomainName"
                if ($PSVersionTable.PSVersion.Major -lt 6) {
                    $CurrentCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                    try {
                        $Response = Invoke-WebRequest -Method Options -Uri $EndpointDomainName -UseBasicParsing -TimeoutSec 3
                        if ($Response.Headers["x-amz-request-id"]) {
                            $Server.S3EndpointUrl = [System.UriBuilder]::new($EndpointDomainName)
                            [System.Net.ServicePointManager]::CertificatePolicy = $CurrentCertificatePolicy
                            break
                        }
                    }
                    catch {
                    }
                    try {
                        $Response = Invoke-WebRequest -Method Options -Uri "$EndpointDomainName/info" -UseBasicParsing -TimeoutSec 3 -SkipCertificateCheck
                        if ($Response.Headers["X-Trans-Id"]) {
                            $Server.SwiftEndpointUrl = [System.UriBuilder]::new($EndpointDomainName)
                            [System.Net.ServicePointManager]::CertificatePolicy = $CurrentCertificatePolicy
                            break
                        }
                    }
                    catch {
                    }
                    [System.Net.ServicePointManager]::CertificatePolicy = $CurrentCertificatePolicy
                }
                else {
                    try {
                        $Response = Invoke-WebRequest -Method Options -Uri "$EndpointDomainName" -SkipCertificateCheck -UseBasicParsing -TimeoutSec 3
                        if ($Response.Headers["x-amz-request-id"]) {
                            Write-Verbose "Test"
                            $Server.S3EndpointUrl = [System.UriBuilder]::new($EndpointDomainName)
                            break
                        }
                    }
                    catch {
                    }
                    try {
                        $Response = Invoke-WebRequest -Method Options -Uri "$EndpointDomainName/info" -SkipCertificateCheck -UseBasicParsing -TimeoutSec 3
                        if ($Response.Headers["X-Trans-Id"]) {
                            $Server.SwiftEndpointUrl = [System.UriBuilder]::new($EndpointDomainName)
                            break
                        }
                    }
                    catch {
                    }
                }
            }
        }
        elseif (!$Server.S3EndpointUrl -and $CurrentSgwServer.Name -eq $Name) {
            Write-Verbose "Setting S3 and Swift Endpoints to the values from current SGW Server"
            $Server.S3EndpointUrl = $CurrentSgwServer.S3EndpointUrl
            $Server.SwiftEndpointUrl = $CurrentSgwServer.SwiftEndpointUrl
        }

        if (!$Transient) {
            Set-Variable -Name CurrentSgwServer -Value $Server -Scope Global
        }

        return $Server
    }
}

<#
    .SYNOPSIS
    Disconnect to StorageGRID Webscale Management Server
    .DESCRIPTION
    Disconnect to StorageGRID Webscale Management Server
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
#>
function global:Disconnect-SgwServer {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
            Remove-Variable -Name CurrentSgwServer -Scope Global
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/authorize"

        $Method = "DELETE"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
            return
        }
    }
}

## compliance ##

# complete as of API 2.2

<#
    .SYNOPSIS
    Retrieves the global compliance settings
    .DESCRIPTION
    Retrieves the global compliance settings
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwCompliance {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.2) {
            Throw "Managing Container Compliance is only Supported from StorageGRID 11.1"
        }
    }

    Process {
        if ($Server.AccountId) {
            $Uri = $Server.BaseURI + "/org/compliance-global"
        }
        else {
            $Uri = $Server.BaseURI + "/grid/compliance-global"
        }

        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Enable Grid wide compliance
    .DESCRIPTION
    Enable Grid wide compliance
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Enable-SgwCompliance {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
        if ($Server.APIVersion -lt 2.2) {
            Throw "Managing Container Compliance is only Supported from StorageGRID 11.1"
        }
    }

    Process {
        $ConfirmComplianceEnabling = $Host.UI.PromptForChoice("Enable Complaince",
                        "Cannot disable Grid wide Compliance on $($Server.Name) after it has been enabled. Still continue?",
                        @("&Yes", "&No"),
                        1)
        if ($ConfirmComplianceEnabling -eq 1) {
            break
        }

        $Uri = $Server.BaseURI + "/grid/compliance-global"
        $Method = "PUT"

        $Body = ConvertTo-Json -InputObject @{complianceEnabled=$true}

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## config ##

# complete as of API 2.2

<#
    .SYNOPSIS
    Retrieves global configuration and token information
    .DESCRIPTION
    Retrieves global configuration and token information
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwConfig {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieves the global management API and UI configuration
    .DESCRIPTION
    Retrieves the global management API and UI configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwConfigManagement {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Changes the global management API and UI configuration
    .DESCRIPTION
    Changes the global management API and UI configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER MinApiVersion
    Minimum API Version.
#>
function Global:Update-SgwConfigManagement {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Minimum API Version.")][Int][ValidateSet(1, 2)]$MinApiVersion
    )


    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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

        $Body = ConvertTo-Json -InputObject @{ minApiVersion = $MinApiVersion }

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Server.SupportedApiVersions = @(Get-SgwVersions -Server $Server)

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieve StorageGRID Product Version
    .DESCRIPTION
    Retrieve StorageGRID Product Version
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwProductVersion {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data.productVersion
    }
}

<#
    .SYNOPSIS
    Retrieves the current API version of the management API
    .DESCRIPTION
    Retrieves the current API version of the management API
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwVersion {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/versions"
        $Method = "GET"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
            $ApiVersion = $Response.Json.APIVersion
        }
        Catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Write-Host "$ResponseBody"
            if ($ResponseBody -match "apiVersion") {
                $ApiVersion = ($ResponseBody | ConvertFrom-Json).APIVersion
            }
            else {
                Write-Warning "Certificate of the server may not be trusted. Use -SkipCertificateCheck switch if you want to skip certificate verification."
                Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
            }
        }

        Write-Output $ApiVersion
    }
}

<#
    .SYNOPSIS
    Retrieves the major versions of the management API supported by the product release
    .DESCRIPTION
    Retrieves the major versions of the management API supported by the product release
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwVersions {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/versions"
        $Method = "GET"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## containers ##

# complete as of API 2.2

Set-Alias -Name Get-SgwBucketOwner -Value Get-SgwContainerOwner
<#
    .SYNOPSIS
    Retrieves the Owner of an S3 bucket or Swift container
    .DESCRIPTION
    Retrieves the Owner of an S3 bucket or Swift container
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    Swift Container or S3 Bucket name.
#>
function Global:Get-SgwContainerOwner {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Swift Container or S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        foreach ($Account in (Get-SgwAccounts -Server $Server)) {
            if ($Account | Get-SgwAccountUsage  -Server $Server | select -ExpandProperty buckets | ? { $_.name -eq $Name } | Select -First 1) {
                Write-Output $Account
                break
            }
        }
    }
}

Set-Alias -Name Get-SgwBuckets -Value Get-SgwContainers
<#
    .SYNOPSIS
    Lists the S3 buckets or Swift containers for a tenant account
    .DESCRIPTION
    Lists the S3 buckets or Swift containers for a tenant account
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwContainers {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "Include complaince and / or region information in response.")][ValidateSet("compliance","region")][String[]]$Include
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers"
        $Method = "GET"

        $IncludeString = $Include -join ","
        if ($IncludeString) {
            $Uri += "?include=$IncludeString"
        }

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Include -match "compliance") {
            $Response.Json.data | Add-Member -MemberType ScriptProperty -Name autoDelete -Value { $this.compliance.autoDelete }
            $Response.Json.data | Add-Member -MemberType ScriptProperty -Name legalHold -Value { $this.compliance.legalHold }
            $Response.Json.data | Add-Member -MemberType ScriptProperty -Name retentionPeriodMinutes -Value { $this.compliance.retentionPeriodMinutes }
        }

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name New-SgwBucket -Value New-SgwContainer
<#
    .SYNOPSIS
    Create a bucket for an S3 tenant account
    .DESCRIPTION
    Create a bucket for an S3 tenant account
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:New-SgwContainer {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "Bucket name (must be DNS-compatible).",
                ValueFromPipelineByPropertyName = $True)][String]$Name,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "The region for this bucket, which must already be defined (defaults to us-east-1 if not specified).",
                ValueFromPipelineByPropertyName = $True)][String]$Region="us-east-1",
        [parameter(
                Mandatory = $False,
                Position = 4,
                HelpMessage = "If specified, Objects in this bucket will be deleted automatically when their retention period expires, unless the bucket is under a legal hold.",
                ValueFromPipelineByPropertyName = $True)][Switch]$AutoDelete,
        [parameter(
                Mandatory = $False,
                Position = 5,
                HelpMessage = "If specified, the objects in the bucket will be put under a legal hold (objects cannot be deleted).",
                ValueFromPipelineByPropertyName = $True)][Switch]$LegalHold,
        [parameter(
                Mandatory = $False,
                Position = 6,
                HelpMessage = "The length of the retention period for objects added to this bucket, in minutes, starting when the object is ingested into the grid.",
                ValueFromPipelineByPropertyName = $True)][ValidateRange(1,[Int]::MaxValue)][Int]$RetentionPeriodMinutes
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.2) {
            Throw "Managing Containers is only Supported from StorageGRID 11.1"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers"
        $Method = "POST"

        $ContainerCreate = @{
            name = $Name;
            region = $Region;
        }

        if ($AutoDelete.IsPresent -or $LegalHold.IsPresent -or $RetentionPeriodMinutes) {
            $ContainerCreate.Compliance = @{
                autoDelete = $AutoDelete.IsPresent;
                legalHold = $LegalHold.IsPresent;
            }
            if ($RetentionPeriodMinutes) {
                $ContainerCreate.Compliance.retentionPeriodMinutes = $RetentionPeriodMinutes
            }
        }

        $Body = ConvertTo-Json -InputObject $ContainerCreate

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Get-SgwBucketCompliance -Value Get-SgwContainerCompliance
<#
    .SYNOPSIS
    Gets the compliance settings for an S3 bucket
    .DESCRIPTION
    Gets the compliance settings for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    Swift Container or S3 Bucket name.
#>
function Global:Get-SgwContainerCompliance {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Swift Container or S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.2) {
            Throw "Managing Container Compliance is only Supported from StorageGRID 11.1"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/compliance"
        $Method = "GET"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Response.Json.data | Add-Member -MemberType NoteProperty -Name Name -Value $Name

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Update-SgwBucketCompliance -Value Update-SgwContainerCompliance
<#
    .SYNOPSIS
    Update the compliance settings for an S3 bucket
    .DESCRIPTION
    Update the compliance settings for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    Swift Container or S3 Bucket name.
    .PARAMETER AutoDelete
    If specified, Objects in this bucket will be deleted automatically when their retention period expires, unless the bucket is under a legal hold.
    .PARAMETER LegalHold
    If specified, the objects in the bucket will be put under a legal hold (objects cannot be deleted).
    .PARAMETER RetentionPeriodMinutes
    The length of the retention period for objects added to this bucket, in minutes, starting when the object is ingested into the grid.
#>
function Global:Update-SgwContainerCompliance {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Swift Container or S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "If specified, Objects in this bucket will be deleted automatically when their retention period expires, unless the bucket is under a legal hold.",
                ValueFromPipelineByPropertyName = $True)][Switch]$AutoDelete,
        [parameter(
                Mandatory = $False,
                Position = 4,
                HelpMessage = "If specified, the objects in the bucket will be put under a legal hold (objects cannot be deleted).",
                ValueFromPipelineByPropertyName = $True)][Switch]$LegalHold,
        [parameter(
                Mandatory = $False,
                Position = 5,
                HelpMessage = "The length of the retention period for objects added to this bucket, in minutes, starting when the object is ingested into the grid.",
                ValueFromPipelineByPropertyName = $True)][ValidateRange(1,[Int]::MaxValue)][Int]$RetentionPeriodMinutes
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.2) {
            Throw "Managing Container Compliance is only Supported from StorageGRID 11.1"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/compliance"
        $Method = "PUT"

        $ContainerComplianceSettings = @{
            autoDelete              = $autoDelete.IsPresent;
            legalHold               = $LegalHold.IsPresent;
            retentionPeriodMinutes  = $RetentionPeriodMinutes
        }

        $Body = ConvertTo-Json -InputObject $ContainerComplianceSettings

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Response.Json.data | Add-Member -MemberType NoteProperty -Name Name -Value $Name

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Get-SgwBucketConsistency -Value Get-SgwContainerConsistency
<#
    .SYNOPSIS
    Gets the consistency level for an S3 bucket or Swift container
    .DESCRIPTION
    Gets the consistency level for an S3 bucket or Swift container
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    Swift Container or S3 Bucket name.
#>
function Global:Get-SgwContainerConsistency {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Swift Container or S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/consistency"
        $Method = "GET"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Response.Json.data | Add-Member -MemberType NoteProperty -Name Name -Value $Name

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Update-SgwBucketConsistency -Value Update-SgwContainerConsistency
<#
    .SYNOPSIS
    Updates the consistency level for an S3 bucket or Swift container
    .DESCRIPTION
    Updates the consistency level for an S3 bucket or Swift container
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    Swift Container or S3 Bucket name.
    .PARAMETER Consistency
    Consistency level.
#>
function Global:Update-SgwContainerConsistency {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Swift Container or S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name,
        [parameter(Mandatory = $True,
                Position = 3,
                HelpMessage = "Consistency level.")][ValidateSet("all", "strong-global", "strong-site", "default", "available", "weak")][String]$Consistency
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/consistency"
        $Method = "PUT"

        $Body = @{ consistency = $Consistency }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Response.Json.data | Add-Member -MemberType NoteProperty -Name Name -Value $Name

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Get-SgwBucketLastAccessTime -Value Get-SgwContainerLastAccessTime
<#
    .SYNOPSIS
    Determines if last access time is enabled for an S3 bucket
    .DESCRIPTION
    Determines if last access time is enabled for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
#>
function Global:Get-SgwContainerLastAccessTime {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/last-access-time"
        $Method = "GET"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Response.Json.data | Add-Member -MemberType NoteProperty -Name Name -Value $Name

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Enable-SgwBucketLastAccessTime -Value Enable-SgwContainerLastAccessTime
<#
    .SYNOPSIS
    Enables last access time updates for an S3 bucket
    .DESCRIPTION
    Enables last access time updates for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
#>
function Global:Enable-SgwContainerLastAccessTime {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/last-access-time"
        $Method = "PUT"

        $Body = @{ lastAccessTime = "enabled" }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Response.Json.data | Add-Member -MemberType NoteProperty -Name Name -Value $Name

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Disable-SgwBucketLastAccessTime -Value Disable-SgwContainerLastAccessTime
<#
    .SYNOPSIS
    Disables last access time updates for an S3 bucket
    .DESCRIPTION
    Disables last access time updates for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
#>
function Global:Disable-SgwContainerLastAccessTime {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/last-access-time"
        $Method = "PUT"

        $Body = @{ lastAccessTime = "disabled" }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Response.Json.data | Add-Member -MemberType NoteProperty -Name Name -Value $Name

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Get-SgwBucketMetadataNotification -Value Get-SgwContainerMetadataNotification
Set-Alias -Name Get-SgwBucketMetadataNotificationRules -Value Get-SgwContainerMetadataNotification
Set-Alias -Name Get-SgwContainerMetadataNotificationRules -Value Get-SgwContainerMetadataNotification
<#
    .SYNOPSIS
    Gets the metadata notification (search) configuration for an S3 bucket
    .DESCRIPTION
    Gets the metadata notification (search) configuration for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
#>
function Global:Get-SgwContainerMetadataNotification {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/metadata-notification"
        $Method = "GET"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Response.Json.data.metadataNotification) {
            $Xml = [xml]$Response.Json.data.metadataNotification
            foreach ($Rule in $Xml.MetadataNotificationConfiguration.Rule) {
                $Rule = [PSCustomObject]@{ Bucket = $Name; Id = $Rule.ID; Status = $Rule.Status; Prefix = $Rule.Prefix; DestinationUrn = $Rule.Destination.Urn }
                Write-Output $Rule
            }
        }
    }
}

Set-Alias -Name Remove-SgwBucketMetadataNotification -Value Remove-SgwContainerMetadataNotification
<#
    .SYNOPSIS
    Romoves the metadata notification (search) configuration for an S3 bucket
    .DESCRIPTION
    Removes the metadata notification (search) configuration for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
#>
function Global:Remove-SgwContainerMetadataNotification {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Swift Container or S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/metadata-notification"
        $Method = "PUT"

        $Body = @{ }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }
    }
}

Set-Alias -Name Update-SgwBucketMetadataNotificationRule -Value Add-SgwContainerMetadataNotificationRule
Set-Alias -Name Update-SgwContainerMetadataNotificationRule -Value Add-SgwContainerMetadataNotificationRule
Set-Alias -Name Add-SgwBucketMetadataNotificationRule -Value Add-SgwContainerMetadataNotificationRule
<#
    .SYNOPSIS
    Adds a new rule for metadata notification (search) configuration for an S3 bucket
    .DESCRIPTION
    Adds a new rule for metadata notification (search) configuration for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
    .PARAMETER Id
    Rule ID - should be a short descriptive string.
    .PARAMETER Status
    Rule Status.
    .PARAMETER Prefix
    S3 Key Prefix.
    .PARAMETER DestinationUrn
    URN of the Destination.
#>
function Global:Add-SgwContainerMetadataNotificationRule {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 1,
                HelpMessage = "Swift Container or S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "Rule ID - should be a short descriptive string.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "Rule Status.")][ValidateSet("Enabled", "Disabled")][String]$Status = "Enabled",
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "S3 Key Prefix.")][String]$Prefix = "",
        [parameter(Mandatory = $True,
                Position = 4,
                HelpMessage = "URN of the Destination.")][Alias("Urn")][System.UriBuilder]$DestinationUrn
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/metadata-notification"
        $Method = "PUT"

        $MetadataNotificationRules = [System.Collections.ArrayList]::new()
        $MetadataNotification = Get-SgwContainerMetadataNotification -Server $Server -Name $Name
        foreach ($MetadataNotificationRule in $MetadataNotification) {
            $Null = $MetadataNotificationRules.Add($MetadataNotificationRule)
        }

        if (($MetadataNotificationRules | Where-Object { $_.Id -eq $Id })) {
            $MetadataNotificationRule = $MetadataNotificationRules | Where-Object { $_.Id -eq $Id } | Select -first 1
            if ($Status) {
                $MetadataNotificationRule.Status = $Status
            }
            if ($Prefix) {
                $MetadataNotificationRule.Prefix = $Prefix
            }
            if ($DestinationUrn) {
                $MetadataNotificationRule.DestinationUrn = $DestinationUrn
            }
        }
        else {
            $MetadataNotificationRule = [PSCustomObject]@{ Id = $ID; Status = $Status; Prefix = $Prefix; DestinationUrn = $DestinationUrn }
            $Null = $MetadataNotificationRules.Add($MetadataNotificationRule)
        }

        $MetadataNotificationConfiguration = "<MetadataNotificationConfiguration>"
        foreach ($MetadataNotificationRule in $MetadataNotificationRules) {
            $MetadataNotificationConfiguration += "<Rule><ID>$( $MetadataNotificationRule.Id )</ID><Status>$( $MetadataNotificationRule.Status )</Status><Prefix>$( $MetadataNotificationRule.Prefix )</Prefix><Destination><Urn>$( $MetadataNotificationRule.DestinationUrn )</Urn></Destination></Rule>"
        }
        $MetadataNotificationConfiguration += "</MetadataNotificationConfiguration>"

        $Body = @{ metadataNotification = $MetadataNotificationConfiguration }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Response.Json.data.metadataNotification) {
            $Xml = [xml]$Response.Json.data.metadataNotification
            foreach ($Rule in $Xml.MetadataNotificationConfiguration.Rule) {
                $Rule = [PSCustomObject]@{ Bucket = $Name; Id = $Rule.ID; Status = $Rule.Status; Prefix = $Rule.Prefix; DestinationUrn = $Rule.Destination.Urn }
                Write-Output $Rule
            }
        }
    }
}

Set-Alias -Name Remove-SgwBucketMetadataNotificationRule -Value Remove-SgwContainerMetadataNotificationRule
<#
    .SYNOPSIS
    Removes a rule for metadata notification (search) configuration for an S3 bucket
    .DESCRIPTION
    Removes a rule for metadata notification (search) configuration for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
    .PARAMETER Id
    Rule ID.
#>
function Global:Remove-SgwContainerMetadataNotificationRule {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Swift Container or S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name,
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "Rule ID.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/metadata-notification"
        $Method = "PUT"

        $MetadataNotificationRules = [System.Collections.ArrayList]::new()
        $MetadataNotification = Get-SgwContainerMetadataNotification -Server $Server -Name $Name
        foreach ($MetadataNotificationRule in $MetadataNotification) {
            if ($MetadataNotificationRule.id -ne $Id) {
                $Null = $MetadataNotificationRules.Add($MetadataNotificationRule)
            }
        }

        $MetadataNotification = "<MetadataNotificationConfiguration>"
        foreach ($MetadataNotificationRule in $MetadataNotificationRules) {
            $MetadataNotification += "<Rule><ID>$( $MetadataNotificationRule.Id )</ID><Status>$( $MetadataNotificationRule.Status )</Status><Prefix>$( $MetadataNotificationRule.Prefix )</Prefix><Destination><Urn>$( $MetadataNotificationRule.DestinationUrn )</Urn></Destination></Rule>"
        }
        $MetadataNotification += "</MetadataNotificationConfiguration>"

        $Body = @{ metadataNotification = $MetadataNotification }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Response.Json.data.metadataNotification) {
            $Xml = [xml]$Response.Json.data.metadataNotification
            foreach ($Rule in $Xml.MetadataNotificationConfiguration.Rule) {
                $Rule = [PSCustomObject]@{ Bucket = $Name; Id = $Rule.ID; Status = $Rule.Status; Prefix = $Rule.Prefix; DestinationUrn = $Rule.Destination.Urn }
                Write-Output $Rule
            }
        }
    }
}

Set-Alias -Name Get-SgwBucketNotification -Value Get-SgwContainerNotification
Set-Alias -Name Get-SgwBucketNotificationRules -Value Get-SgwContainerNotification
Set-Alias -Name Get-SgwBucketNotificationTopics -Value Get-SgwContainerNotification
Set-Alias -Name Get-SgwContainerNotificationRules -Value Get-SgwContainerNotification
Set-Alias -Name Get-SgwContainerNotificationTopics -Value Get-SgwContainerNotification
<#
    .SYNOPSIS
    Gets the notification configuration for an S3 bucket
    .DESCRIPTION
    Gets the notification configuration for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
#>
function Global:Get-SgwContainerNotification {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/notification"
        $Method = "GET"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Response.Json.data.notification) {
            Write-Verbose $Response.Json.data.notification
            $Xml = [xml]$Response.Json.data.notification
            foreach ($Topic in $Xml.NotificationConfiguration.TopicConfiguration) {
                $Topic = [PSCustomObject]@{ Bucket = $Name; Id = $Topic.Id; Topic = $Topic.Topic; Event = $Topic.Event; Prefix = ($Topic.Filter.S3Key.FilterRule | ? { $_.Name -eq "prefix" } | Select -ExpandProperty Value -First 1); Suffix = ($Topic.Filter.S3Key.FilterRule | ? { $_.Name -eq "suffix" } | Select -ExpandProperty Value -First 1) }
                Write-Output $Topic
            }
        }
    }
}

Set-Alias -Name Remove-SgwBucketNotification -Value Remove-SgwContainerNotification
<#
    .SYNOPSIS
    Remove the notification configuration for an S3 bucket
    .DESCRIPTION
    Remove the notification configuration for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
#>
function Global:Remove-SgwContainerNotification {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/notification"
        $Method = "PUT"

        $Body = @{ }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }
    }
}

Set-Alias -Name Add-SgwBucketNotificationRule -Value Add-SgwContainerNotificationTopic
Set-Alias -Name Add-SgwBucketNotificationTopic -Value Add-SgwContainerNotificationTopic
Set-Alias -Name Add-SgwContainerNotificationRule -Value Add-SgwContainerNotificationTopic
<#
    .SYNOPSIS
    Add a topic to the notification configuration for an S3 bucket
    .DESCRIPTION
    Add a topic to the notification configuration for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
    .PARAMETER Id
    Topic ID - should be a short descriptive string.
    .PARAMETER Topic
    URN of the Topic.
    .PARAMETER Events
    Events to trigger notifications for.
    .PARAMETER Prefix
    Prefix filter.
    .PARAMETER Suffix
    Suffix filter.
#>
function Global:Add-SgwContainerNotificationTopic {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name,
        [parameter(Mandatory = $True,
                Position = 3,
                HelpMessage = "Topic ID - should be a short descriptive string.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id,
        [parameter(Mandatory = $True,
                Position = 4,
                HelpMessage = "URN of the Topic.")][Alias("TopicUrn", "Urn")][System.UriBuilder]$Topic,
        [parameter(Mandatory = $False,
                Position = 5,
                HelpMessage = "Events to trigger notifications for.")][Alias("Event")][String[]]$Events,
        [parameter(Mandatory = $False,
                Position = 6,
                HelpMessage = "Prefix filter.")][String]$Prefix,
        [parameter(Mandatory = $False,
                Position = 7,
                HelpMessage = "Suffix filter.")][String]$Suffix
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/notification"
        $Method = "PUT"

        $NotificationTopics = [System.Collections.ArrayList]::new()
        $Notifications = Get-SgwContainerNotification -Server $Server -Name $Name
        foreach ($NotificationTopic in $Notifications) {
            $Null = $NotificationTopics.Add($NotificationTopic)
        }

        if (($NotificationTopics | Where-Object { $_.Id -eq $Id })) {
            $NotificationTopic = $NotificationTopics | Where-Object { $_.Id -eq $Id } | Select -first 1
            if ($Topic) {
                $NotificationTopic.Topic = $Topic
            }
            if ($Events) {
                $NotificationTopic.Events = $Events
            }
            if ($Prefix) {
                $NotificationTopic.Prefix = $Prefix
            }
            if ($Suffix) {
                $NotificationTopic.Suffix = $Suffix
            }
        }
        else {
            $NotificationTopic = [PSCustomObject]@{ Id = $ID; Topic = $Topic; Events = $Events; Prefix = $Prefix; Suffix = $Suffix }
            $Null = $NotificationTopics.Add($NotificationTopic)
        }

        $NotificationConfiguration = "<NotificationConfiguration>"
        foreach ($NotificationTopic in $NotificationTopics) {
            $NotificationConfiguration += "<TopicConfiguration><Id>$( $NotificationTopic.Id )</Id><Topic>$( $NotificationTopic.Topic )</Topic>"
            foreach ($Event in $Events) {
                $NotificationConfiguration += "<Event>$Event</Event>"
            }
            $NotificationConfiguration += "<Filter><S3Key><FilterRule><Name>prefix</Name><Value>$( $NotificationTopic.Prefix )</Value></FilterRule><FilterRule><Name>suffix</Name><Value>$( $NotificationTopic.Suffix )</Value></FilterRule></S3Key></Filter></TopicConfiguration>"
        }
        $NotificationConfiguration += "</NotificationConfiguration>"

        $Body = @{ notification = $NotificationConfiguration }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Response.Json.data.notification) {
            Write-Verbose $Response.Json.data.notification
            $Xml = [xml]$Response.Json.data.notification
            foreach ($Topic in $Xml.NotificationConfiguration.TopicConfiguration) {
                $Topic = [PSCustomObject]@{ Bucket = $Name; Id = $Topic.Id; Topic = $Topic.Topic; Event = $Topic.Event; Prefix = ($Topic.Filter.S3Key.FilterRule | ? { $_.Name -eq "prefix" } | Select -ExpandProperty Value -First 1); Suffix = ($Topic.Filter.S3Key.FilterRule | ? { $_.Name -eq "suffix" } | Select -ExpandProperty Value -First 1) }
                Write-Output $Topic
            }
        }
    }
}

Set-Alias -Name Remove-SgwBucketNotificationRule -Value Remove-SgwContainerNotificationTopic
Set-Alias -Name Remove-SgwBucketNotificationTopic -Value Remove-SgwContainerNotificationTopic
Set-Alias -Name Remove-SgwContainerNotificationRule -Value Remove-SgwContainerNotificationTopic
<#
    .SYNOPSIS
    Remove a topic from the notification configuration for an S3 bucket
    .DESCRIPTION
    Remove a topic from the notification configuration for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
    .PARAMETER Id
    Topic ID.
#>
function Global:Remove-SgwContainerNotificationTopic {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Swift Container or S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name,
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "Topic ID.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/notification"
        $Method = "PUT"

        $NotificationTopics = [System.Collections.ArrayList]::new()
        $Notifications = Get-SgwContainerNotification -Server $Server -Name $Name
        foreach ($NotificationTopic in $Notifications) {
            if ($NotificationTopic.id -ne $Id) {
                $Null = $NotificationTopics.Add($NotificationTopic)
            }
        }

        if (($NotificationTopics | Where-Object { $_.Id -eq $Id })) {
            $NotificationTopic = $NotificationTopics | Where-Object { $_.Id -eq $Id } | Select -first 1
            if ($Topic) {
                $NotificationTopic.Topic = $Topic
            }
            if ($Events) {
                $NotificationTopic.Events = $Events
            }
            if ($Prefix) {
                $NotificationTopic.Prefix = $Prefix
            }
            if ($Suffix) {
                $NotificationTopic.Suffix = $Suffix
            }
        }
        else {
            $NotificationTopic = [PSCustomObject]@{ Id = $ID; Topic = $Topic; Events = $Events; Prefix = $Prefix; Suffix = $Suffix }
            $Null = $NotificationTopics.Add($NotificationTopic)
        }

        $NotificationConfiguration = "<NotificationConfiguration>"
        foreach ($NotificationTopic in $NotificationTopics) {
            $NotificationConfiguration += "<TopicConfiguration><Id>$( $NotificationTopic.Id )</Id><Topic>$( $NotificationTopic.Topic )</Topic>"
            foreach ($Event in $Events) {
                $NotificationConfiguration += "<Event>$Event</Event>"
            }
            $NotificationConfiguration += "<Filter><S3Key><FilterRule><Name>prefix</Name><Value>$( $NotificationTopic.Prefix )</Value></FilterRule><FilterRule><Name>suffix</Name><Value>$( $NotificationTopic.Suffix )</Value></FilterRule></S3Key></Filter></TopicConfiguration>"
        }
        $NotificationConfiguration += "</NotificationConfiguration>"

        $Body = @{ metadataNotification = $MetadataNotification }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Response.Json.data.notification) {
            Write-Verbose $Response.Json.data.notification
            $Xml = [xml]$Response.Json.data.notification
            foreach ($Topic in $Xml.NotificationConfiguration.TopicConfiguration) {
                $Topic = [PSCustomObject]@{ Bucket = $Name; Id = $Topic.Id; Topic = $Topic.Topic; Event = $Topic.Event; Prefix = ($Topic.Filter.S3Key.FilterRule | ? { $_.Name -eq "prefix" } | Select -ExpandProperty Value -First 1); Suffix = ($Topic.Filter.S3Key.FilterRule | ? { $_.Name -eq "suffix" } | Select -ExpandProperty Value -First 1) }
                Write-Output $Topic
            }
        }
    }
}

Set-Alias -Name Get-SgwBucketReplication -Value Get-SgwContainerReplication
Set-Alias -Name Get-SgwBucketReplicationRules -Value Get-SgwContainerReplication
Set-Alias -Name Get-SgwContainerReplicationRules -Value Get-SgwContainerReplication
<#
    .SYNOPSIS
    Gets the replication configuration for an S3 bucket
    .DESCRIPTION
    Gets the replication configuration for an S3 bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
#>
function Global:Get-SgwContainerReplication {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/replication"
        $Method = "GET"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Response.Json.data.replication) {
            $Xml = [xml]$Response.Json.data.replication
            foreach ($Rule in $Xml.ReplicationConfiguration.Rule) {
                $Rule = [PSCustomObject]@{ Bucket = $Name; Id = $Rule.ID; Status = $Rule.Status; Prefix = $Rule.Prefix; DestinationUrn = $Rule.Destination.Bucket; DestinationStorageClass = $Rule.Destination.StorageClass }
                Write-Output $Rule
            }
        }
    }
}

Set-Alias -Name Remove-SgwBucketReplication -Value Remove-SgwContainerReplication
<#
    .SYNOPSIS
    Removes the replication configuration for an S3 bucket or Swift container
    .DESCRIPTION
    Removes the replication configuration for an S3 bucket or Swift container
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
#>
function Global:Remove-SgwContainerReplication {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/replication"
        $Method = "PUT"

        $Body = @{ }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }
    }
}

Set-Alias -Name Update-SgwBucketReplicationRule -Value Add-SgwContainerReplicationRule
Set-Alias -Name Update-SgwBucketReplicationRule -Value Add-SgwContainerReplicationRule
Set-Alias -Name Add-SgwBucketReplicationRule -Value Add-SgwContainerReplicationRule
<#
    .SYNOPSIS
    Adds a replication configuration rule for an S3 bucket or Swift container
    .DESCRIPTION
    Adds a replication configuration rule for an S3 bucket or Swift container
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
    .PARAMETER Id
    Rule ID - a short descriptive string.
    .PARAMETER Status
    Rule Status.
    .PARAMETER Prefix
    S3 Key Prefix.
    .PARAMETER DestinationBucket
    Destination Bucket name.
    .PARAMETER DestinationUrn
    Destination Bucket URN.
    .PARAMETER DestinationStorageClass
    Destination Storage Class.
    .PARAMETER Role
    IAM Role.
#>
function Global:Add-SgwContainerReplicationRule {
    [CmdletBinding(DefaultParameterSetName = "bucket")]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Swift Container or S3 Bucket name to be replicated.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name,
        [parameter(Mandatory = $True,
                Position = 3,
                HelpMessage = "Rule ID - a short descriptive string.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id,
        [parameter(Mandatory = $False,
                Position = 4,
                HelpMessage = "Rule Status.")][ValidateSet("Enabled", "Disabled")][String]$Status = "Enabled",
        [parameter(Mandatory = $False,
                Position = 5,
                HelpMessage = "S3 Key Prefix.")][String]$Prefix = "",
        [parameter(Mandatory = $True,
                Position = 6,
                ParameterSetName = "bucket",
                HelpMessage = "Destination Bucket name.")][String]$DestinationBucket,
        [parameter(Mandatory = $True,
                Position = 6,
                ParameterSetName = "urn",
                HelpMessage = "Destination Bucket URN.")][String]$DestinationUrn,
        [parameter(Mandatory = $False,
                Position = 7,
                HelpMessage = "Destination Storage Class.")][ValidateSet("STANDARD", "STANDARD_IA", "RRS")][String]$DestinationStorageClass = "STANDARD",
        [parameter(Mandatory = $False,
                Position = 8,
                HelpMessage = "IAM Role.")][String]$Role
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/replication"
        $Method = "PUT"

        $ReplicationRules = [System.Collections.ArrayList]::new()
        $Replication = Get-SgwContainerReplication -Server $Server -Name $Name
        foreach ($ReplicationRule in $Replication) {
            $Null = $ReplicationRules.Add($ReplicationRule)
        }

        if ($DestinationBucket) {
            $DestinationUrn = Get-SgwEndpoints | Where-Object { $_.endpointURN -match ":$DestinationBucket$" } | Select-Object -ExpandProperty endpointURN -First 1
        }

        if (($ReplicationRules | Where-Object { $_.Id -eq $Id })) {
            $ReplicationRule = $ReplicationRules | Where-Object { $_.Id -eq $Id } | Select -first 1
            if ($Status) {
                $ReplicationRule.Status = $Status
            }
            if ($Prefix) {
                $ReplicationRule.Prefix = $Prefix
            }
            $ReplicationRule.DestinationUrn = $DestinationUrn
            if ($DestinationStorageClass) {
                $ReplicationRule.DestinationStorageClass = $DestinationStorageClass
            }
            if ($Role) {
                $ReplicationRule.Role = $Role
            }
        }
        else {
            $ReplicationRule = [PSCustomObject]@{ Id = $ID; Status = $Status; Prefix = $Prefix; DestinationUrn = $DestinationUrn; DestinationStorageClass = $DestinationStorageClass; Role = $Role }
            $Null = $ReplicationRules.Add($ReplicationRule)
        }

        $ReplicationConfiguration = "<ReplicationConfiguration>"
        foreach ($ReplicationRule in $ReplicationRules) {
            $ReplicationConfiguration += "<Rule><ID>$( $ReplicationRule.Id )</ID><Status>$( $ReplicationRule.Status )</Status><Prefix>$( $ReplicationRule.Prefix )</Prefix><Destination><Bucket>$( $ReplicationRule.DestinationUrn )</Bucket><StorageClass>$( $ReplicationRule.DestinationStorageClass )</StorageClass></Destination><Role>$( $ReplicationRule.Role )</Role></Rule>"
        }
        $ReplicationConfiguration += "</ReplicationConfiguration>"

        $Body = @{ replication = $ReplicationConfiguration }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Response.Json.data.replication) {
            $Xml = [xml]$Response.Json.data.replication
            foreach ($Rule in $Xml.ReplicationConfiguration.Rule) {
                $Rule = [PSCustomObject]@{ Bucket = $Name; Id = $Rule.ID; Status = $Rule.Status; Prefix = $Rule.Prefix; DestinationUrn = $Rule.Destination.Bucket; DestinationStorageClass = $Rule.Destination.StorageClass }
                Write-Output $Rule
            }
        }
    }
}

Set-Alias -Name Remove-SgwBucketReplicationRule -Value Remove-SgwContainerReplicationRule
<#
    .SYNOPSIS
    Removes a replication configuration rule for an S3 bucket or Swift container
    .DESCRIPTION
    Removes a replication configuration rule for an S3 bucket or Swift container
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Name
    S3 Bucket name.
    .PARAMETER Id
    Rule ID.
#>
function Global:Remove-SgwContainerReplicationRule {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Swift Container or S3 Bucket name.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("Container", "Bucket","ContainerName","BucketName")][String]$Name,
        [parameter(Mandatory = $True,
                Position = 3,
                HelpMessage = "Rule ID.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Containers is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/containers/$Name/replication"
        $Method = "PUT"

        $ReplicationRules = [System.Collections.ArrayList]::new()
        $Replication = Get-SgwContainerReplication -Server $Server -Name $Name
        foreach ($ReplicationRule in $Replication) {
            if ($ReplicationRule.id -ne $Id) {
                $Null = $ReplicationRules.Add($ReplicationRule)
            }
        }

        $ReplicationConfiguration = "<ReplicationConfiguration>"
        foreach ($ReplicationRule in $ReplicationRules) {
            $ReplicationConfiguration += "<Rule><ID>$( $ReplicationRule.Id )</ID><Status>$( $ReplicationRule.Status )</Status><Prefix>$( $ReplicationRule.Prefix )</Prefix><Destination><Bucket>$( $ReplicationRule.DestinationUrn )</Bucket><StorageClass>$( $ReplicationRule.DestinationStorageClass )</StorageClass></Destination><Role>$( $ReplicationRule.Role )</Role></Rule>"
        }
        $ReplicationConfiguration += "</ReplicationConfiguration>"

        $Body = @{ replication = $ReplicationConfiguration }
        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Response.Json.data.replication) {
            $Xml = [xml]$Response.Json.data.replication
            foreach ($Rule in $Xml.ReplicationConfiguration.Rule) {
                $Rule = [PSCustomObject]@{ Bucket = $Name; Id = $Rule.ID; Status = $Rule.Status; Prefix = $Rule.Prefix; DestinationUrn = $Rule.Destination.Bucket; DestinationStorageClass = $Rule.Destination.StorageClass }
                Write-Output $Rule
            }
        }
    }
}

## deactivated-features ##

# complete as of API 2.2

<#
    .SYNOPSIS
    Retrieves the deactivated features configuration
    .DESCRIPTION
    Retrieves the deactivated features configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwDeactivatedFeatures {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Deactivates specific features. If no feature is selected, all features will be enabled again.
    .DESCRIPTION
    Deactivates specific features. If no feature is selected, all features will be enabled again.
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER AlarmAcknowledgment
    Deactivate ability to acknowledge alarms.
    .PARAMETER OtherGridConfiguration
    Deactivate ability to access configuration pages not covered by other permissions.
    .PARAMETER GridTopologyPageConfiguration
    Deactivate ability to access Grid Topology configuration tabs and modify otherGridConfiguration pages.
    .PARAMETER TenantAccounts
    Deactivate ability to add, edit, or remove tenant accounts (The deprecated management API v1 also uses this permission to manage tenant group policies, reset Swift admin passwords, and manage root user S3 access keys.).
    .PARAMETER ChangeTenantRootPassword
    Deactivate ability to reset the root user password for tenant accounts.
    .PARAMETER Maintenance
    Deactivate ability to perform maintenance procedures: software upgrade, expansion, decommission, and Recovery Package download; ability to configure DNS servers, NTP servers, grid license, domain names, server certificates, and audit; ability to collect logs.
    .PARAMETER MetricsQuery
    Deactivate ability to perform custom Prometheus metrics queries.
    .PARAMETER ActivateFeatures
    Deactivates ability to reactivate features that have been deactivated via the deactivated-features endpoints (This permission is provided for the option of deactivating it for security; the deactivated-features endpoints require rootAccess, so it is not useful to grant this permission to groups. Warning: this permission itself cannot be reactivated once deactivated, except by technical support.)
    .PARAMETER Ilm
    Deactivates ability to add, edit, or set ILM policies, ILM rules, and EC profiles; ability to simulate ILM evaluation of objects on the grid.)
    .PARAMETER ObjectMetadata
    Deactivates ability to look up object metadata for any object stored on the grid.)
    .PARAMETER ManageAllContainers
    Deactivates ability to manage all S3 buckets or Swift containers for this tenant account (overrides permission settings in group or bucket policies).
    .PARAMETER ManageEndpoints
    Deactivates ability to manage all S3 endpoints for this tenant account.
    .PARAMETER ManageOwnS3Credentials
    Deactivates ability to manage your personal S3 credentials.
#>
function Global:Update-SgwDeactivatedFeatures {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "Deactivate ability to acknowledge alarms.")][Boolean]$AlarmAcknowledgment,
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "Deactivate ability to access configuration pages not covered by other permissions.")][Boolean]$OtherGridConfiguration,
        [parameter(Mandatory = $False,
                Position = 4,
                HelpMessage = "Deactivate ability to access Grid Topology configuration tabs and modify otherGridConfiguration pages.")][Boolean]$GridTopologyPageConfiguration,
        [parameter(Mandatory = $False,
                Position = 5,
                HelpMessage = "Deactivate ability to add, edit, or remove tenant accounts (The deprecated management API v1 also uses this permission to manage tenant group policies, reset Swift admin passwords, and manage root user S3 access keys.).")][Boolean]$TenantAccounts,
        [parameter(Mandatory = $False,
                Position = 6,
                HelpMessage = "Deactivate ability to reset the root user password for tenant accounts.")][Boolean]$ChangeTenantRootPassword,
        [parameter(Mandatory = $False,
                Position = 7,
                HelpMessage = "Deactivate ability to perform maintenance procedures: software upgrade, expansion, decommission, and Recovery Package download; ability to configure DNS servers, NTP servers, grid license, domain names, server certificates, and audit; ability to collect logs.")][Boolean]$Maintenance,
        [parameter(Mandatory = $False,
                Position = 8,
                HelpMessage = "Deactivate ability to perform custom Prometheus metrics queries.")][Boolean]$MetricsQuery,
        [parameter(Mandatory = $False,
                Position = 9,
                HelpMessage = "Deactivates ability to reactivate features that have been deactivated via the deactivated-features endpoints (This permission is provided for the option of deactivating it for security; the deactivated-features endpoints require rootAccess, so it is not useful to grant this permission to groups. Warning: this permission itself cannot be reactivated once deactivated, except by technical support.)")][Boolean]$ActivateFeatures,
        [parameter(Mandatory = $False,
                Position = 10,
                HelpMessage = "Deactivates ability to add, edit, or set ILM policies, ILM rules, and EC profiles; ability to simulate ILM evaluation of objects on the grid.)")][Boolean]$Ilm,
        [parameter(Mandatory = $False,
                Position = 11,
                HelpMessage = "Deactivates ability to look up object metadata for any object stored on the grid.)")][Boolean]$ObjectMetadata,
        [parameter(Mandatory = $False,
                Position = 12,
                HelpMessage = "Deactivates ability to manage all S3 buckets or Swift containers for this tenant account (overrides permission settings in group or bucket policies).")][Boolean]$ManageAllContainers,
        [parameter(Mandatory = $False,
                Position = 13,
                HelpMessage = "Deactivates ability to manage all S3 endpoints for this tenant account.")][Boolean]$ManageEndpoints,
        [parameter(Mandatory = $False,
                Position = 14,
                HelpMessage = "Deactivates ability to manage your personal S3 credentials.")][Boolean]$ManageOwnS3Credentials
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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

        $Body = @{ }
        if ($AlarmAcknowledgment -or $OtherGridConfiguration -or $GridTopologyPageConfiguration -or $TenantAccounts -or $ChangeTenantRootPassword -or $Maintenance -or $ActivateFeatures) {
            $Body.grid = @{ }
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
        if ($MetricsQuery) {
            $Body.grid.metricsQuery = $MetricsQuery
        }
        if ($ActivateFeatures) {
            $caption = "Please Confirm"
            $message = "Are you sure you want to proceed with permanently deactivating the activation of features (this can't be undone!):"
            [int]$defaultChoice = 0
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Do the job."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Do not do the job."
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($no, $yes)
            $choiceRTN = $host.ui.PromptForChoice($caption, $message, $options, $defaultChoice)
            if ($choiceRTN -eq 1) {
                $Body.grid.activateFeatures = $ActivateFeatures
            }
            else {
                Write-Host "Deactivating of permanent feature activation aborted."
                return
            }
        }
        if ($Ilm) {
            $Body.grid.ilm = $Ilm
        }
        if ($ObjectMetadata) {
            $Body.grid.objectMetadata = $ObjectMetadata
        }
        if ($ManageAllContainers -or $ManageEndpoints -or $ManageOwnS3Credentials) {
            $Body.tenant = @{}
        }
        if ($ManageAllContainers) {
            $Body.tenant.manageAllContainers = $ManageAllContainers
        }
        if ($ManageEndpoints) {
            $Body.tenant.manageEndpoints = $ManageEndpoints
        }
        if ($ManageOwnS3Credentials) {
            $Body.tenant.manageOwnS3Credentials = $ManageOwnS3Credentials
        }
        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## dns-servers ##

# complete as of API 2.2

<#
    .SYNOPSIS
    Retrieve StorageGRID DNS Servers
    .DESCRIPTION
    Retrieve StorageGRID DNS Servers
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwDnsServers {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/dns-servers"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieve StorageGRID DNS Servers
    .DESCRIPTION
    Retrieve StorageGRID DNS Servers
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER DnsServers
    List of IP addresses of the external DNS servers.
#>
function Global:Replace-SgwDnsServers {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "List of IP addresses of the external DNS servers.")][String[]]$DnsServers
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## endpoints ##

<#
    .SYNOPSIS
    Gets the list of endpoints
    .DESCRIPTION
    Gets the list of endpoints
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwEndpoints {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName="default"
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Endpoints is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/endpoints"
        $Method = "GET"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name New-SgwEndpoint -Value Add-SgwEndpoint
<#
    .SYNOPSIS
    Creates a new endpoint
    .DESCRIPTION
    Creates a new endpoint
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER DisplayName
    Display Name of Endpoint.
    .PARAMETER EndpointUri
    URI of the Endpoint.
    .PARAMETER EndpointUrn
    URN of the Endpoint.
    .PARAMETER CaCert
    CA Certificate String.
    .PARAMETER SkipCertificateCheck
    Skip endpoint certificate check.
    .PARAMETER AccessKey
    S3 Access Key authorized to use the endpoint.
    .PARAMETER SecretAccessKey
    S3 Secret Access Key authorized to use the endpoint.
    .PARAMETER Test
    Test the validity of the endpoint but do not save it.
    .PARAMETER Force
    Force saving without endpoint validation.
#>
function Global:Add-SgwEndpoint {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName="default",
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Display Name of Endpoint.")][String]$DisplayName,
        [parameter(Mandatory = $True,
                Position = 3,
                HelpMessage = "URI of the Endpoint.")][Alias("Uri")][System.UriBuilder]$EndpointUri,
        [parameter(Mandatory = $True,
                Position = 4,
                HelpMessage = "URN of the Endpoint.")][Alias("Urn")][System.UriBuilder]$EndpointUrn,
        [parameter(Mandatory = $False,
                Position = 5,
                HelpMessage = "CA Certificate String.")][String]$CaCert,
        [parameter(Mandatory = $False,
                Position = 6,
                HelpMessage = "Skip endpoint certificate check.")][Alias("insecureTLS")][Switch]$SkipCertificateCheck,
        [parameter(Mandatory = $False,
                Position = 7,
                HelpMessage = "S3 Access Key authorized to use the endpoint.")][String]$AccessKey,
        [parameter(Mandatory = $False,
                Position = 8,
                HelpMessage = "S3 Secret Access Key authorized to use the endpoint.")][String]$SecretAccessKey,
        [parameter(Mandatory = $False,
                Position = 9,
                HelpMessage = "Test the validity of the endpoint but do not save it.")][Switch]$Test,
        [parameter(Mandatory = $False,
                Position = 10,
                HelpMessage = "Force saving without endpoint validation.")][Alias("ForceSave")][Switch]$Force
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Endpoints is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/endpoints"
        $Method = "POST"

        if ($Test.isPresent) {
            $Uri += "?test=true"
        }
        elseif ($Force.isPresent) {
            $Uri += "?forceSave=true"
        }

        $EndpointBucketName = $EndpointUrn.Uri.ToString() -replace ".*:.*:.*:.*:.*:(.*)",'$1'
        # Convert Destination Bucket Name to IDN mapping to support Unicode Names
        $EndpointBucketName = [System.Globalization.IdnMapping]::new().GetAscii($EndpointBucketName).ToLower()
        $EndpointUrnPrefix = $EndpointUrn.Uri.ToString() -replace "(.*:.*:.*:.*:.*:).*",'$1'
        $EndpointUrn = [System.UriBuilder]"$EndpointUrnPrefix$EndpointBucketName"

        $Body = @{ }
        $Body.displayName = $DisplayName
        $Body.endpointURI = $EndpointUri.Uri
        $Body.endpointURN = $EndpointUrn.Uri
        $Body.caCert = $CaCert
        $Body.insecureTLS = $SkipCertificateCheck.isPresent
        $Body.credentials = @{ }
        $Body.credentials.accessKeyId = $AccessKey
        $Body.credentials.secretAccessKey = $SecretAccessKey

        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Remove-SgwS3Endpoint -Value Remove-SgwEndpoint
Set-Alias -Name Remove-SgwSnsEndpoint -Value Remove-SgwEndpoint
Set-Alias -Name Remove-SgwEsEndpoint -Value Remove-SgwEndpoint
<#
    .SYNOPSIS
    Deletes a single endpoint
    .DESCRIPTION
    Deletes a single endpoint
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    Endpoint ID.
#>
function Global:Remove-SgwEndpoint {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName="default",
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Endpoint ID.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Endpoints is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/endpoints/$Id"
        $Method = "DELETE"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Get-SgwS3Endpoint -Value Get-SgwEndpoint
Set-Alias -Name Get-SgwSnsEndpoint -Value Get-SgwEndpoint
Set-Alias -Name Get-SgwEsEndpoint -Value Get-SgwEndpoint
<#
    .SYNOPSIS
    Retrieves a single endpoint
    .DESCRIPTION
    Retrieves a single endpoint
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    Endpoint ID.
#>
function Global:Get-SgwEndpoint {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName="default",
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Endpoint ID.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Endpoints is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/endpoints/$Id"
        $Method = "GET"

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Replaces a single endpoint
    .DESCRIPTION
    Replaces a single endpoint
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    Endpoint ID.
    .PARAMETER DisplayName
    Display Name of Endpoint.
    .PARAMETER EndpointUri
    URI of the Endpoint.
    .PARAMETER EndpointUrn
    URN of the Endpoint.
    .PARAMETER Region
    Region
    .PARAMETER Name
    Bucket Name for CloudMirror, Topic Name for SNS or Domain-Name/Index-Name/Type-Name for ElasticSearch.
    .PARAMETER CaCert
    CA Certificate String.
    .PARAMETER SkipCertificateCheck
    Skip endpoint certificate check.
    .PARAMETER S3Profile
    S3 Profile which has credentials and region to be used for this endpoint.
    .PARAMETER AccessKey
    S3 Access Key authorized to use the endpoint.
    .PARAMETER SecretAccessKey
    S3 Secret Access Key authorized to use the endpoint.
    .PARAMETER Test
    Test the validity of the endpoint but do not save it.
    .PARAMETER Force
    Force saving without endpoint validation.
#>
function Global:Update-SgwEndpoint {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName="default",
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Endpoint ID.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id,
        [parameter(Mandatory = $True,
                Position = 3,
                HelpMessage = "Display Name of Endpoint.")][String]$DisplayName,
        [parameter(Mandatory = $False,
                Position = 4,
                ParameterSetName = "UriAndUrnAndProfile",
                HelpMessage = "URI of the Endpoint.")]
        [parameter(Mandatory = $False,
                Position = 4,
                ParameterSetName = "UriAndUrnAndKey",
                HelpMessage = "URI of the Endpoint.")]
        [parameter(Mandatory = $False,
                Position = 4,
                ParameterSetName = "UriAndNameAndProfile",
                HelpMessage = "URI of the Endpoint.")]
        [parameter(Mandatory = $False,
                Position = 4,
                ParameterSetName = "UriAndNameAndKey",
                HelpMessage = "URI of the Endpoint.")][Alias("Uri")][System.UriBuilder]$EndpointUri,
        [parameter(Mandatory = $False,
                Position = 5,
                ParameterSetName = "UriAndUrnAndProfile",
                HelpMessage = "URN of the Endpoint.")]
        [parameter(Mandatory = $False,
                Position = 5,
                ParameterSetName = "UriAndUrnAndKey",
                HelpMessage = "URN of the Endpoint.")]
        [parameter(Mandatory = $False,
                Position = 5,
                ParameterSetName = "RegionAndUrnAndProfile",
                HelpMessage = "URN of the Endpoint.")]
        [parameter(Mandatory = $False,
                Position = 5,
                ParameterSetName = "RegionAndUrnAndKey",
                HelpMessage = "URN of the Endpoint.")][Alias("Urn")][System.UriBuilder]$EndpointUrn,
        [parameter(Mandatory = $False,
                Position = 4,
                ParameterSetName = "RegionAndUrnAndProfile",
                HelpMessage = "Region.")]
        [parameter(Mandatory = $False,
                Position = 4,
                ParameterSetName = "RegionAndUrnAndKey",
                HelpMessage = "Region.")]
        [parameter(Mandatory = $False,
                Position = 4,
                ParameterSetName = "RegionAndNameAndProfile",
                HelpMessage = "Region.")]
        [parameter(Mandatory = $False,
                Position = 4,
                ParameterSetName = "RegionAndNameAndKey",
                HelpMessage = "Region.")][String]$Region,
        [parameter(Mandatory = $False,
                Position = 5,
                ParameterSetName = "RegionAndNameAndProfile",
                HelpMessage = "Bucket Name for CloudMirror, Topic Name for SNS or Domain-Name/Index-Name/Type-Name for ElasticSearch.")]
        [parameter(Mandatory = $False,
                Position = 5,
                ParameterSetName = "RegionAndNameAndKey",
                HelpMessage = "Bucket Name for CloudMirror, Topic Name for SNS or Domain-Name/Index-Name/Type-Name for ElasticSearch.")]
        [parameter(Mandatory = $False,
                Position = 5,
                ParameterSetName = "UriAndNameAndProfile",
                HelpMessage = "Bucket Name for CloudMirror, Topic Name for SNS or Domain-Name/Index-Name/Type-Name for ElasticSearch.")]
        [parameter(Mandatory = $False,
                Position = 5,
                ParameterSetName = "UriAndNameAndKey",
                HelpMessage = "Bucket Name for CloudMirror, Topic Name for SNS or Domain-Name/Index-Name/Type-Name for ElasticSearch.")]
        [parameter(Mandatory = $False,
                Position = 5,
                ParameterSetName = "NameOnlyAndProfile",
                HelpMessage = "Bucket Name for CloudMirror, Topic Name for SNS or Domain-Name/Index-Name/Type-Name for ElasticSearch.")]
        [parameter(Mandatory = $False,
                Position = 5,
                ParameterSetName = "NameOnlyAndKey",
                HelpMessage = "Bucket Name for CloudMirror, Topic Name for SNS or Domain-Name/Index-Name/Type-Name for ElasticSearch.")][Alias("Bucket", "BucketName", "Topic", "Domain")][String]$Name,
        [parameter(Mandatory = $False,
                Position = 6,
                HelpMessage = "CA Certificate String.")][String]$CaCert,
        [parameter(Mandatory = $False,
                Position = 7,
                HelpMessage = "Skip endpoint certificate check.")][Alias("insecureTLS")][Switch]$SkipCertificateCheck,
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "UriAndUrnAndProfile",
                HelpMessage = "S3 Profile which has credentials and region to be used for this endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "UriAndNameAndProfile",
                HelpMessage = "S3 Profile which has credentials and region to be used for this endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "RegionAndUrnAndProfile",
                HelpMessage = "S3 Profile which has credentials and region to be used for this endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "RegionAndNameAndProfile",
                HelpMessage = "S3 Profile which has credentials and region to be used for this endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "NameOnlyAndProfile",
                HelpMessage = "S3 Profile which has credentials and region to be used for this endpoint.")][String]$S3Profile = "default",
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "UriAndUrnAndKey",
                HelpMessage = "S3 Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "UriAndNameAndKey",
                HelpMessage = "S3 Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "RegionAndUrnAndKey",
                HelpMessage = "S3 Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "RegionAndNameAndKey",
                HelpMessage = "S3 Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "NameOnlyAndKey",
                HelpMessage = "S3 Access Key authorized to use the endpoint.")][Alias("AccessKeyId")][String]$AccessKey,
        [parameter(Mandatory = $False,
                Position = 9,
                ParameterSetName = "UriAndUrnAndKey",
                HelpMessage = "S3 Secret Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 9,
                ParameterSetName = "UriAndNameAndKey",
                HelpMessage = "S3 Secret Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 9,
                ParameterSetName = "RegionAndUrnAndKey",
                HelpMessage = "S3 Secret Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 9,
                ParameterSetName = "RegionAndNameAndKey",
                HelpMessage = "S3 Secret Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 9,
                ParameterSetName = "NameOnlyAndKey",
                HelpMessage = "S3 Secret Access Key authorized to use the endpoint.")][String]$SecretAccessKey,
        [parameter(Mandatory = $False,
                Position = 10,
                HelpMessage = "Test the validity of the endpoint but do not save it.",
                ParameterSetName = "test")][Switch]$Test,
        [parameter(Mandatory = $False,
                Position = 11,
                HelpMessage = "Force saving without endpoint validation.",
                ParameterSetName = "force")][Alias("ForceSave")][Switch]$Force
    )

    Begin {
        if (!$ProfileName -and !$Server -and !$CurrentSgwServer.Name) {
            $ProfileName = "default"
        }
        if ($ProfileName) {
            $Profile = Get-SgwProfile -ProfileName $ProfileName
            if (!$Profile.Name) {
                Throw "Profile $ProfileName not found. Create a profile using New-SgwProfile or connect to a StorageGRID Server using Connect-SgwServer"
            }
            $Server = Connect-SgwServer -Name $Profile.Name -Credential $Profile.Credential -AccountId $Profile.AccountId -SkipCertificateCheck:$Profile.SkipCertificateCheck -DisableAutomaticAccessKeyGeneration:$Profile.disalble_automatic_access_key_generation -TemporaryAccessKeyExpirationTime $Profile.temporary_access_key_expiration_time -S3EndpointUrl $Profile.S3EndpointUrl -SwiftEndpointUrl $Profile.SwiftEndpointUrl -Transient
        }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.APIVersion -lt 2.1) {
            Throw "Managing Endpoints is only Supported from StorageGRID 11.0"
        }
        if (!$Server.AccountId) {
            throw "Not connected as tenant user. Use Connect-SgwServer with the parameter accountId to connect to a tenant."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/org/endpoints/$id"
        $Method = "PUT"

        if ($Test.isPresent) {
            $Uri += "?test=true"
        }
        elseif ($Force.isPresent) {
            $Uri += "?forceSave=true"
        }

        if ($S3Profile) {
            $Config = Get-AwsCredential -Profile $S3Profile
            if (!$Config.aws_access_key_id -and !$Config.aws_secret_access_key) {
                throw "No Credentials found for Profile $S3Profile. Either add credentials using Add-AwsCredential or specify AccessKey and SecretAccessKey"
            }
            $AccessKey = $Config.aws_access_key_id
            $SecretAccessKey = $Config.aws_secret_access_key
            if (!$Region -and $Name -and !$EndpointUri) {
                if ($Config.Region) {
                    $Region = $Config.Region
                    if ($Region -eq "us-east-1" -and !$Config.endpoint_url) {
                        $EndpointUri = "s3.amazonaws.com"
                    }
                    elseif (!$Config.endpoint_url) {
                        $EndpointUri = "s3.$Region.amazonaws.com"
                    }
                    else {
                        $EndpointUri = [System.UriBuilder]$Config.endpoint_url
                    }
                }
                else {
                    Throw "No Endpoint URI and Region specified and Region not included in configuration of profile $S3Profile"
                }
            }
        }

        if ($Name) {
            if ($EndpointUri -match "amazonaws.com") {
                $EndpointUrn = "arn:aws:s3:::$Name"
            }
            else {
                $EndpointUrn = "urn:sgws:s3:::$Name"
            }
        }

        $Body = @{ }
        $Body.displayName = $DisplayName
        $Body.endpointURI = $EndpointUri.Uri
        $Body.endpointURN = $EndpointUrn.Uri
        $Body.caCert = $CaCert
        $Body.insecureTLS = $SkipCertificateCheck.isPresent
        $Body.credentials = @{ }
        $Body.credentials.accessKeyId = $AccessKey
        $Body.credentials.secretAccessKey = $SecretAccessKey

        $Body = ConvertTo-Json -InputObject $Body

        Try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Gets the list of S3 endpoints
    .DESCRIPTION
    Gets the list of S3 endpoints
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
#>
function Global:Get-SgwS3Endpoints {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName="default"
    )

    Process {
        Get-SgwEndpoints -Server $Server -ProfileName $ProfileName | Where-Object { $_.endpointURN -match "[^:]*:[^:]*:s3:" }
    }
}

Set-Alias -Name New-SgwS3Endpoint -Value Add-SgwS3Endpoint
<#
    .SYNOPSIS
    Creates a new S3 endpoint
    .DESCRIPTION
    Creates a new S3 endpoint
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER DisplayName
    Display Name of Endpoint.
    .PARAMETER Region
    Region
    .PARAMETER Name
    Bucket Name
    .PARAMETER CaCert
    CA Certificate String.
    .PARAMETER SkipCertificateCheck
    Skip endpoint certificate check.
    .PARAMETER AccessKey
    S3 Access Key authorized to use the endpoint.
    .PARAMETER SecretAccessKey
    S3 Secret Access Key authorized to use the endpoint.
    .PARAMETER Test
    Test the validity of the endpoint but do not save it.
    .PARAMETER Force
    Force saving without endpoint validation.
#>
function Global:Add-SgwS3Endpoint {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName="default",
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Display Name of Endpoint.")][String]$DisplayName,
        [parameter(Mandatory = $True,
                Position = 3,
                ParameterSetName = "RegionAndName",
                HelpMessage = "Region.")][String]$Region,
        [parameter(Mandatory = $True,
                Position = 4,
                ParameterSetName = "RegionAndName",
                HelpMessage = "Bucket Name.")]
        [parameter(Mandatory = $True,
                Position = 4,
                ParameterSetName = "NameOnly",
                HelpMessage = "Bucket Name.")][Alias("Bucket","Name")][String]$BucketName,
        [parameter(Mandatory = $False,
                Position = 5,
                HelpMessage = "CA Certificate String.")][String]$CaCert,
        [parameter(Mandatory = $False,
                Position = 6,
                HelpMessage = "Skip endpoint certificate check.")][Alias("insecureTLS")][Switch]$SkipCertificateCheck,
        [parameter(Mandatory = $False,
                Position = 7,
                ParameterSetName = "RegionAndName",
                HelpMessage = "StorageGRID Profile which has credentials and region to be used for this endpoint.")]
        [parameter(Mandatory = $False,
                Position = 7,
                ParameterSetName = "NameOnly",
                HelpMessage = "StorageGRID Profile which has credentials and region to be used for this endpoint.")][String]$S3Profile = "default",
        [parameter(Mandatory = $False,
                Position = 7,
                ParameterSetName = "RegionAndName",
                HelpMessage = "S3 Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 7,
                ParameterSetName = "NameOnly",
                HelpMessage = "S3 Access Key authorized to use the endpoint.")][String]$AccessKey,
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "RegionAndName",
                HelpMessage = "S3 Secret Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "NameOnly",
                HelpMessage = "S3 Secret Access Key authorized to use the endpoint.")][String]$SecretAccessKey,
        [parameter(Mandatory = $False,
                Position = 9,
                HelpMessage = "Test the validity of the endpoint but do not save it.",
                ParameterSetName = "test")][Switch]$Test,
        [parameter(Mandatory = $False,
                Position = 10,
                HelpMessage = "Force saving without endpoint validation.",
                ParameterSetName = "force")][Alias("ForceSave")][Switch]$Force
    )

    Process {
        if ($S3Profile) {
            $Config = Get-AwsCredential -Profile $S3Profile
            if (!$Config.aws_access_key_id -and !$Config.aws_secret_access_key) {
                throw "No Credentials found for Profile $S3Profile. Either add credentials using Add-AwsCredential or specify AccessKey and SecretAccessKey"
            }
            $AccessKey = $Config.aws_access_key_id
            $SecretAccessKey = $Config.aws_secret_access_key
            if (!$Region -and $Config.Region) {
                $Region = $Config.Region
            }
        }

        if (!$Region) {
            $Region = "us-east-1"
        }

        if (!$EndpointUri) {
            if ($Region -eq "us-east-1" -and !$Config.endpoint_url) {
                $EndpointUri = "https://s3.amazonaws.com"
            }
            elseif (!$Config.endpoint_url) {
                $EndpointUri = "https://s3.$Region.amazonaws.com"
            }
            else {
                $EndpointUri = [System.UriBuilder]$Config.endpoint_url
            }
        }

        if ($Name) {
            if ($EndpointUri -match "amazonaws.com") {
                $EndpointUrn = "arn:aws:s3:::$Name"
            }
            else {
                $EndpointUrn = "urn:sgws:s3:::$Name"
            }
        }

        Add-SgwEndpoint -Server $Server -ProfileName $ProfileName -DisplayName $DisplayName -EndpointUri $EndpointUri -EndpointUrn $EndpointUrn -CaCert $CaCert -SkipCertificateCheck:$SkipCertificateCheck -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -Test:$Test -Force:$Force
    }
}

<#
    .SYNOPSIS
    Update S3 endpoint
    .DESCRIPTION
    Update S3 endpoint
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER ProfileName
    StorageGRID Profile to use for connection.
    .PARAMETER Id
    Endpoint ID.
    .PARAMETER DisplayName
    Display Name of Endpoint.
    .PARAMETER Region
    Region
    .PARAMETER Name
    Bucket Name
    .PARAMETER CaCert
    CA Certificate String.
    .PARAMETER SkipCertificateCheck
    Skip endpoint certificate check.
    .PARAMETER AccessKey
    S3 Access Key authorized to use the endpoint.
    .PARAMETER SecretAccessKey
    S3 Secret Access Key authorized to use the endpoint.
    .PARAMETER Test
    Test the validity of the endpoint but do not save it.
    .PARAMETER Force
    Force saving without endpoint validation.
#>
function Global:Add-SgwS3Endpoint {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Profile to use for connection.")][Alias("Profile")][String]$ProfileName="default",
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "Endpoint ID.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id,
        [parameter(Mandatory = $True,
                Position = 3,
                HelpMessage = "Display Name of Endpoint.")][String]$DisplayName,
        [parameter(Mandatory = $True,
                Position = 4,
                ParameterSetName = "RegionAndName",
                HelpMessage = "Region.")][String]$Region,
        [parameter(Mandatory = $True,
                Position = 5,
                ParameterSetName = "RegionAndName",
                HelpMessage = "Bucket Name.")]
        [parameter(Mandatory = $True,
                Position = 5,
                ParameterSetName = "NameOnly",
                HelpMessage = "Bucket Name.")][Alias("Bucket","Name")][String]$BucketName,
        [parameter(Mandatory = $False,
                Position = 6,
                HelpMessage = "CA Certificate String.")][String]$CaCert,
        [parameter(Mandatory = $False,
                Position = 7,
                HelpMessage = "Skip endpoint certificate check.")][Alias("insecureTLS")][Switch]$SkipCertificateCheck,
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "RegionAndName",
                HelpMessage = "StorageGRID Profile which has credentials and region to be used for this endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "NameOnly",
                HelpMessage = "StorageGRID Profile which has credentials and region to be used for this endpoint.")][String]$S3Profile = "default",
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "RegionAndName",
                HelpMessage = "S3 Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 8,
                ParameterSetName = "NameOnly",
                HelpMessage = "S3 Access Key authorized to use the endpoint.")][String]$AccessKey,
        [parameter(Mandatory = $False,
                Position = 9,
                ParameterSetName = "RegionAndName",
                HelpMessage = "S3 Secret Access Key authorized to use the endpoint.")]
        [parameter(Mandatory = $False,
                Position = 9,
                ParameterSetName = "NameOnly",
                HelpMessage = "S3 Secret Access Key authorized to use the endpoint.")][String]$SecretAccessKey,
        [parameter(Mandatory = $False,
                Position = 10,
                HelpMessage = "Test the validity of the endpoint but do not save it.",
                ParameterSetName = "test")][Switch]$Test,
        [parameter(Mandatory = $False,
                Position = 11,
                HelpMessage = "Force saving without endpoint validation.",
                ParameterSetName = "force")][Alias("ForceSave")][Switch]$Force
    )

    Process {
        if ($S3Profile) {
            $Config = Get-AwsCredential -Profile $S3Profile
            if (!$Config.aws_access_key_id -and !$Config.aws_secret_access_key) {
                throw "No Credentials found for Profile $S3Profile. Either add credentials using Add-AwsCredential or specify AccessKey and SecretAccessKey"
            }
            $AccessKey = $Config.aws_access_key_id
            $SecretAccessKey = $Config.aws_secret_access_key
            if (!$Region -and $Config.Region) {
                $Region = $Config.Region
            }
        }

        if (!$Region) {
            $Region = "us-east-1"
        }

        if (!$EndpointUri) {
            if ($Region -eq "us-east-1" -and !$Config.endpoint_url) {
                $EndpointUri = "https://s3.amazonaws.com"
            }
            elseif (!$Config.endpoint_url) {
                $EndpointUri = "https://s3.$Region.amazonaws.com"
            }
            else {
                $EndpointUri = [System.UriBuilder]$Config.endpoint_url
            }
        }

        if ($Name) {
            if ($EndpointUri -match "amazonaws.com") {
                $EndpointUrn = "arn:aws:s3:::$Name"
            }
            else {
                $EndpointUrn = "urn:sgws:s3:::$Name"
            }
        }

        Update-SgwEndpoint -Server $Server -ProfileName $ProfileName -Id $Id -DisplayName $DisplayName -EndpointUri $EndpointUri -EndpointUrn $EndpointUrn -CaCert $CaCert -SkipCertificateCheck:$SkipCertificateCheck -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -Test:$Test -Force:$Force
    }
}

## endpoint-domain-names ##

# complete as of API 2.1

<#
    .SYNOPSIS
    Lists endpoint domain names
    .DESCRIPTION
    Lists endpoint domain names
#>
function Global:Get-SgwEndpointDomainNames {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/domain-names"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Add-SgwEndpointDomainNames -Value Replace-SgwEndpointDomainNames
Set-Alias -Name New-SgwEndpointDomainNames -Value Replace-SgwEndpointDomainNames
<#
    .SYNOPSIS
    Change the endpoint domain names
    .DESCRIPTION
    Change the endpoint domain names
#>
function Global:Replace-SgwEndpointDomainNames {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $True,
                Position = 1,
                HelpMessage = "List of DNS names to be used as S3/Swift endpoints.")][String[]]$EndpointDomainNames
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/domain-names"
        $Method = "PUT"

        $Body = ConvertTo-Json -InputObject $EndpointDomainNames

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## erasure-coding

# complete as of API 2.1

<#
    .SYNOPSIS
    Lists EC profiles
    .DESCRIPTION
    Lists EC profiles
#>
function Global:Get-SgwEcProfiles {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/ec-profiles"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## erasure-coding

<#
    .SYNOPSIS
    Lists EC profiles
    .DESCRIPTION
    Lists EC profiles
#>
function Global:Get-SgwEcSchemes {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/schemes"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## expansion ##

# complete as of API 2.1

<#
    .SYNOPSIS
    Cancels the expansion procedure and resets all user configuration of expansion grid nodes
    .DESCRIPTION
    Cancels the expansion procedure and resets all user configuration of expansion grid nodes
#>
function Global:Stop-SgwExpansion {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion"
        $Method = "DELETE"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieves the status of the current expansion procedure
    .DESCRIPTION
    Retrieves the status of the current expansion procedure
#>
function Global:Get-SgwExpansion {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Initiates the expansion procedure, allowing configuration of the expansion grid nodes
    .DESCRIPTION
    Initiates the expansion procedure, allowing configuration of the expansion grid nodes
#>
function Global:Start-SgwExpansion {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/start"
        $Method = "POST"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Executes the expansion procedure, adding configured grid nodes to the grid
    .DESCRIPTION
    Executes the expansion procedure, adding configured grid nodes to the grid
#>
function Global:Invoke-SgwExpansion {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Passphrase.")][String]$Passphrase,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/expand"
        $Method = "POST"

        $Body = ConvertTo-Json -InputObject @{ passphrase = $Passphrase }

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## expansion-nodes ##

# complete as of API 2.1

<#
    .SYNOPSIS
    Retrieves the list of grid nodes available for expansion
    .DESCRIPTION
    Retrieves the list of grid nodes available for expansion
#>
function Global:Get-SgwExpansionNodes {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/nodes"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Removes a grid node from all procedures; the grid node may be added back in by rebooting it
    .DESCRIPTION
    Removes a grid node from all procedures; the grid node may be added back in by rebooting it
#>
function Global:Remove-SgwExpansionNode {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of a StorageGRID Webscale node to remove from expansion.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$id,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/nodes/$id"
        $Method = "DELETE"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieves a grid node eligbible for expansion
    .DESCRIPTION
    Retrieves a grid node eligbible for expansion
#>
function Global:Get-SgwExpansionNode {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of a StorageGRID node eligible for expansion.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$id,
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/nodes/$id"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

# TODO: Implement
<#
    .SYNOPSIS
    Configures a grid node expansion
    .DESCRIPTION
    Configures a grid node expansion
#>
function Global:New-SgwExpansionNode {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/start"
        $Method = "POST"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Resets a grid node's configuration and returns it back to pending state
    .DESCRIPTION
    Resets a grid node's configuration and returns it back to pending state
#>
function Global:Reset-SgwExpansionNode {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of a StorageGRID node eligible for expansion.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$id,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/node/$id"
        $Method = "POST"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## expansion-sites ##

# complete as of API 2.1

<#
    .SYNOPSIS
    Retrieves the list of existing and new sites (empty until expansion is started)
    .DESCRIPTION
    Retrieves the list of existing and new sites (empty until expansion is started)
#>
function Global:Get-SgwExpansionSites {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/sites"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Adds a new site
    .DESCRIPTION
    Adds a new site
#>
function Global:New-SgwExpansionSite {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "Name of new site.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Name,
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/site"
        $Method = "POST"

        $Body = ConvertTo-Json -InputObject @{ name = $Name }

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Delete a site
    .DESCRIPTION
    Delete a site
#>
function Global:Remove-SgwExpansionSite {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of a StorageGRID Webscale site to remove from expansion.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$id,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/sites/$id"
        $Method = "DELETE"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieve a site
    .DESCRIPTION
    Retrieve a site
#>
function Global:Get-SgwExpansionSite {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of a StorageGRID site.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$id,
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/sites/$id"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Updates the details of a site
    .DESCRIPTION
    Updates the details of a site
#>
function Global:Update-SgwExpansionSite {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of a StorageGRID site to be updated.")][String]$ID,
        [parameter(
                Mandatory = $True,
                Position = 1,
                HelpMessage = "New ID for the StorageGRID site.")][String]$NewID,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "New name for the StorageGRID site.")][String]$Name,
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/expansion/site/$id"
        $Method = "PUT"

        $Body = @{ }
        if ($Name) {
            $Body.name = $Name
        }
        if ($NewID) {
            $Body.id = $NewID
        }

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## grid-networks ##

# complete as of API 2.1

<#
    .SYNOPSIS
    Lists the current Grid Networks
    .DESCRIPTION
    Lists the current Grid Networks
#>
function Global:Get-SgwGridNetworks {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/grid-networks"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Change the Grid Network list
    .DESCRIPTION
    Change the Grid Network list
#>
function Global:Update-SgwGridNetworks {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $True,
                Position = 1,
                HelpMessage = "List of grid network Subnets in CIDR format (e.g. 10.0.0.0/16).")][String[]]$Subnets,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "StorageGRID Passphrase.")][String]$Passphrase
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/grid-networks/update"
        $Method = "POST"

        $Body = @{ }
        $Body.passphrase = $Passphrase
        $Body.subnets = $Subnets
        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## groups ##

<#
    .SYNOPSIS
    List Groups
    .DESCRIPTION
    List Groups
#>
function Global:Get-SgwGroups {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

# TODO: Implement adding tenant groups and rename cmdlets
<#
    .SYNOPSIS
    Creates a new Grid Administrator Group
    .DESCRIPTION
    Creates a new Grid Administrator Group
#>
function Global:New-SgwGroup {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory = $True,
                Position = 1,
                HelpMessage = "Display name of the group.")][String]$displayName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "Display name of the group.")][String]$uniqueName,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "Display name of the group.")][Boolean]$alarmAcknowledgment,
        [parameter(
                Mandatory = $False,
                Position = 4,
                HelpMessage = "Display name of the group.")][Boolean]$otherGridConfiguration,
        [parameter(
                Mandatory = $False,
                Position = 5,
                HelpMessage = "Display name of the group.")][Boolean]$gridTopologyPageConfiguration,
        [parameter(
                Mandatory = $False,
                Position = 6,
                HelpMessage = "Display name of the group.")][Boolean]$tenantAccounts,
        [parameter(
                Mandatory = $False,
                Position = 7,
                HelpMessage = "Display name of the group.")][Boolean]$changeTenantRootPassword,
        [parameter(
                Mandatory = $False,
                Position = 8,
                HelpMessage = "Display name of the group.")][Boolean]$maintenance,
        [parameter(
                Mandatory = $False,
                Position = 9,
                HelpMessage = "Display name of the group.")][Boolean]$activateFeatures,
        [parameter(
                Mandatory = $False,
                Position = 10,
                HelpMessage = "Display name of the group.")][Boolean]$rootAccess,
        [parameter(
                Mandatory = $False,
                Position = 11,
                HelpMessage = "IAM Policy.")][PSCustomObject]$IamPolicy,
        [parameter(
                Mandatory = $False,
                Position = 11,
                HelpMessage = "Use IAM Policy for Full S3 Access.")][Switch]$S3FullAccess,
        [parameter(
                Mandatory = $False,
                Position = 11,
                HelpMessage = "Use IAM Policy for Read Only S3 Access.")][Switch]$S3ReadOnlyAccess,
        [parameter(
                Mandatory = $False,
                Position = 12,
                HelpMessage = "Swift Roles.")][String[]]$SwiftRoles
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/groups"
        $Method = "POST"

        $Body = @{ }
        $Body.displayName = $displayName
        $Body.uniqueName = $uniqueName
        if ($alarmAcknowledgment -or $otherGridConfiguration -or $gridTopologyPageConfiguration -or $tenantAccounts -or $changeTenantRootPassword -or $maintenance -or $activateFeatures -or $rootAccess -or $IamPolicy -or $SwiftRoles) {
            $Body.policies = @{ }
            $Body.policies.management = @{ }
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
            if ($Capabilities -match "s3") {
                if (!$IamPolicy -and !($S3FullAccess.IsPresent -or $S3ReadOnlyAccess)) {
                    Write-Warning "S3 capability specified, but no IAM Policy provided. Users of this group will not be able to execute any S3 commands on buckets or objects."
                }
                elseif ($S3FullAccess.IsPresent) {
                    $Body.policies.s3 = New-IamPolicy -Effect "Allow" -Resource "urn:sgws:s3:::*" -Action "s3:*"
                }
                elseif ($S3ReadOnlyAccess.IsPresent) {
                    $Body.policies.s3 = New-IamPolicy -Effect "Allow" -Resource "urn:sgws:s3:::*" -Action "s3:ListBucket", "s3:ListBucketVersions", "s3:ListAllMyBuckets", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts", "s3:GetAccelerateConfiguration", "s3:GetAnalyticsConfiguration", "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketLocation", "s3:GetBucketLogging", "s3:GetBucketNotification", "s3:GetBucketPolicy", "s3:GetBucketRequestPayment", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetBucketWebsite", "s3:GetInventoryConfiguration", "s3:GetIpConfiguration", "s3:GetLifecycleConfiguration", "s3:GetMetricsConfiguration", "s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectTagging", "s3:GetObjectTorrent", "s3:GetObjectVersion", "s3:GetObjectVersionAcl", "s3:GetObjectVersionForReplication", "s3:GetObjectVersionTagging", "s3:GetObjectVersionTorrent", "s3:GetReplicationConfiguration"
                }
                else {
                    $Body.policies.s3 = $IamPolicy
                }
            }

            if ($Capabilities -match "swift") {
                if (!$SwiftRoles) {
                    Write-Warning "Swift capability specified, but no Swift roles specified."
                }
                else {
                    $Body.policies.swift = @{ }
                    $Body.policies.swift.roles = $SwiftRoles
                }
            }
        }

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieves a local Grid Administrator Group by unique name
    .DESCRIPTION
    Retrieves a local Grid Administrator Group by unique name
#>
function Global:Get-SgwGroupByShortName {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "Short name of the user to retrieve.")][String]$ShortName,
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieves a federated Grid Administrator Group by unique name
    .DESCRIPTION
    Retrieves a federated Grid Administrator Group by unique name
#>
function Global:Get-SgwFederatedGroupByShortName {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "Short name of the user to retrieve.")][String]$ShortName,
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Deletes a single Group
    .DESCRIPTION
    Deletes a single Group
#>
function Global:Delete-SgwGroup {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of a StorageGRID Webscale Group to delete.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$id,
        [parameter(
                Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieves a single Group
    .DESCRIPTION
    Retrieves a single Group
#>
function Global:Get-SgwGroup {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of a StorageGRID Webscale Group to retrieve.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$id,
        [parameter(
                Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

# TODO: Implement updating tenant group and rename cmdlet
<#
    .SYNOPSIS
    Updates a single Grid Administrator Group
    .DESCRIPTION
    Updates a single Grid Administrator Group
#>
function Global:Update-SgwGroup {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of the group to be updated.")][String]$ID,
        [parameter(
                Mandatory = $True,
                Position = 1,
                HelpMessage = "Display name of the group.")][String]$displayName,
        [parameter(
                Mandatory = $False,
                Position = 2,
                HelpMessage = "Display name of the group.")][Boolean]$alarmAcknowledgment,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "Display name of the group.")][Boolean]$otherGridConfiguration,
        [parameter(
                Mandatory = $False,
                Position = 4,
                HelpMessage = "Display name of the group.")][Boolean]$gridTopologyPageConfiguration,
        [parameter(
                Mandatory = $False,
                Position = 5,
                HelpMessage = "Display name of the group.")][Boolean]$tenantAccounts,
        [parameter(
                Mandatory = $False,
                Position = 6,
                HelpMessage = "Display name of the group.")][Boolean]$changeTenantRootPassword,
        [parameter(
                Mandatory = $False,
                Position = 7,
                HelpMessage = "Display name of the group.")][Boolean]$maintenance,
        [parameter(
                Mandatory = $False,
                Position = 8,
                HelpMessage = "Display name of the group.")][Boolean]$activateFeatures,
        [parameter(
                Mandatory = $False,
                Position = 9,
                HelpMessage = "Display name of the group.")][Boolean]$rootAccess,
        [parameter(
                Mandatory = $False,
                Position = 10,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/groups"
        $Method = "POST"

        $Body = @{ }
        if ($displayName) {
            $Body.displayName = $displayName
        }
        if ($alarmAcknowledgment -or $otherGridConfiguration -or $gridTopologyPageConfiguration -or $tenantAccounts -or $changeTenantRootPassword -or $maintenance -or $activateFeatures -or $rootAccess) {
            $Body.policies = @{ }
            $Body.policies.management = @{ }
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

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

# TODO: Implement replacing tenant group and rename this cmdlet
<#
    .SYNOPSIS
    Replaces a single Grid Administrator Group
    .DESCRIPTION
    Replaces a single Grid Administrator Group
#>
function Global:Replace-SgwGroup {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of the group to be updated.")][String]$ID,
        [parameter(
                Mandatory = $True,
                Position = 1,
                HelpMessage = "Display name of the group.")][String]$displayName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "Unique name.")][String]$uniqueName,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "Unique name.")][String]$accountId,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "Unique name.")][Boolean]$federated,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "Unique name.")][String]$groupURN,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "Display name of the group.")][Boolean]$alarmAcknowledgment,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "Display name of the group.")][Boolean]$otherGridConfiguration,
        [parameter(
                Mandatory = $False,
                Position = 4,
                HelpMessage = "Display name of the group.")][Boolean]$gridTopologyPageConfiguration,
        [parameter(
                Mandatory = $False,
                Position = 5,
                HelpMessage = "Display name of the group.")][Boolean]$tenantAccounts,
        [parameter(
                Mandatory = $False,
                Position = 6,
                HelpMessage = "Display name of the group.")][Boolean]$changeTenantRootPassword,
        [parameter(
                Mandatory = $False,
                Position = 7,
                HelpMessage = "Display name of the group.")][Boolean]$maintenance,
        [parameter(
                Mandatory = $False,
                Position = 8,
                HelpMessage = "Display name of the group.")][Boolean]$activateFeatures,
        [parameter(
                Mandatory = $False,
                Position = 9,
                HelpMessage = "Display name of the group.")][Boolean]$rootAccess,
        [parameter(
                Mandatory = $False,
                Position = 10,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/groups/$id"
        $Method = "PUT"

        $Body = @{ }
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
            $Body.policies = @{ }
            $Body.policies.management = @{ }
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

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieve groups of a StorageGRID Webscale Account
    .DESCRIPTION
    Retrieve groups of a StorageGRID Webscale Account
#>
function Global:Get-SgwAccountGroups {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "ID of a StorageGRID Webscale Account to get group information for.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$id,
        [parameter(
                Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## health ##

# complete as of API 2.1

<#
    .SYNOPSIS
    Retrieve StorageGRID Health Status
    .DESCRIPTION
    Retrieve StorageGRID Health Status
#>
function Global:Get-SgwHealth {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + '/grid/health'
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieve StorageGRID Topology with Health Status
    .DESCRIPTION
    Retrieve StorageGRID Topology with Health Status
#>
function Global:Get-SgwTopologyHealth {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "Topology depth level to provide (default=node).")][String][ValidateSet("grid", "site", "node", "component", "subcomponent")]$Depth = "node"
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/health/topology?depth=$depth"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## identity-source ##

# complete as of API 2.1

<#
    .SYNOPSIS
    Retrieve identity sources
    .DESCRIPTION
    Retrieve identity sources
#>
function Global:Get-SgwIdentitySources {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieve identity sources
    .DESCRIPTION
    Retrieve identity sources
#>
function Global:Update-SgwIdentitySources {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "Identity Source ID",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Id,
        [parameter(
                Mandatory = $False,
                Position = 1,
                HelpMessage = "Disable Identity Source ID")][Switch]$Disable,
        [parameter(
                Mandatory = $False,
                Position = 2,
                HelpMessage = "Identity Source Hostname")][String]$Hostname,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "Identity Source Port")][Int]$Port,
        [parameter(
                Mandatory = $False,
                Position = 4,
                HelpMessage = "Identity Source Username and password")][PSCredential]$Credential,
        [parameter(
                Mandatory = $False,
                Position = 6,
                HelpMessage = "Identity Source Base Group DN")][String]$BaseGroupDN,
        [parameter(
                Mandatory = $False,
                Position = 7,
                HelpMessage = "Identity Source Base User DN")][String]$BaseUserDN,
        [parameter(
                Mandatory = $False,
                Position = 8,
                HelpMessage = "Identity Source LDAP Service Type")][String]$LdapServiceType,
        [parameter(
                Mandatory = $False,
                Position = 9,
                HelpMessage = "Identity Source Type")][String]$Type,
        [parameter(
                Mandatory = $False,
                Position = 10,
                HelpMessage = "Identity Source LDAP User ID Attribute")][String]$LDAPUserIDAttribute,
        [parameter(
                Mandatory = $False,
                Position = 11,
                HelpMessage = "Identity Source LDAP User UUID Attribute")][String]$LDAPUserUUIDAttribute,
        [parameter(
                Mandatory = $False,
                Position = 12,
                HelpMessage = "Identity Source LDAP Group ID Attribute")][String]$LDAPGroupIDAttribute,
        [parameter(
                Mandatory = $False,
                Position = 13,
                HelpMessage = "Identity Source Disable TLS")][Switch]$DisableTLS,
        [parameter(
                Mandatory = $False,
                Position = 14,
                HelpMessage = "Identity Source CA Certificate")][String]$CACertificate,
        [parameter(
                Mandatory = $False,
                Position = 15,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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

        $Username = $Credential.UserName -replace '([a-zA-Z0-9])\\([a-zA-Z0-9])', '$1\\\\$2'
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieve identity sources
    .DESCRIPTION
    Retrieve identity sources
#>
function Global:Sync-SgwIdentitySources {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body "" -SkipCertificateCheck:$Server.SkipCertificateCheck
            Write-Host "Successfully synchronized users and groups of identity sources"
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
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
function Global:Invoke-SgwIlmEvaluate {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "The object API that the provided object was evaluated against.")][String][ValidateSet('cdmi', 's3', 'swift')]$API,
        [parameter(Mandatory = $True,
                Position = 1,
                HelpMessage = "Protocol-specific object identifier (e.g. bucket/key/1).")][String]$ObjectID,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "Switch indicating that ILM evaluation should occur immediately.")][Switch]$Now,
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/ilm-evaluate"
        $Method = "POST"

        $Body = @{ }
        $Body.objectID = $ObjectID
        if ($API) {
            $Body.api = $API
        }
        if ($Now) {
            $Body.now = Get-Date -Format u
        }

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Lists metadata available for creating an ILM rule
    .DESCRIPTION
    Lists metadata available for creating an ILM rule
#>
function Global:Get-SgwIlmMetadata {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "The object API that the provided object was evaluated against.")][String][ValidateSet('cdmi', 's3', 'swift')]$API,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/ilm-metadata?api=$api"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Lists ILM rules
    .DESCRIPTION
    Lists ILM rules
#>
function Global:Get-SgwIlmRules {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/ilm-rules"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## license ##

# complete as of API 2.1

<#
    .SYNOPSIS
    Retrieves the grid license
    .DESCRIPTION
    Retrieves the grid license
#>
function Global:Get-SgwLicense {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/license"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Update the license
    .DESCRIPTION
    Update the license
#>
function Global:Update-SgwLicense {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale license.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$License,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Passphrase.")][String]$Passphrase,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/license/update"
        $Method = "POST"

        $Body = @{ }
        $Body.passphrase = $Passphrase
        $Body.license = $License

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## logs ##

# complete as of API 2.1

Set-Alias -Name Get-SgwLogStatus -Value Get-SgwLogs
<#
    .SYNOPSIS
    Retrieves the log collection procedure status
    .DESCRIPTION
    Retrieves the log collection procedure status
#>
function Global:Get-SgwLogs {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/logs"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Retrieves the log collection procedure status
    .DESCRIPTION
    Retrieves the log collection procedure status
#>
function Global:Start-SgwLogCollection {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $True,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Passphrase.")][String]$Passphrase,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "List of StorageGRID Nodes to collect logs for (Default: all nodes).")][String[]]$Nodes,
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "First log timestamp at start of log collection (Default: last hour).")][DateTime]$RangeStart=(Get-Date).AddHours(-1),
        [parameter(Mandatory = $False,
                Position = 4,
                HelpMessage = "Last log timestamp at end of log collection (Default: now).")][DateTime]$RangeEnd=(Get-Date)
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/logs/collect"
        $Method = "POST"

        $Topology = Get-SgwTopologyHealth -Server $Server
        $TopologyNodes = $Topology.children.children

        $NodeIds = @()

        foreach ($Node in $Nodes) {
            if (!$TopologyNodes.id.Contains($Node)) {
                if ($TopologyNodes.name.Contains($Node)) {
                    $NodeIds += $TopologyNodes | Where-Object { $_.name -eq $Node } | Select-Object -ExpandProperty id
                }
                else {
                    Throw "Node $Node not found"
                }
            }
            else {
                NodeIds += $Node
            }
        }

        if (!$NodeIds) {
            $NodeIds = $TopologyNodes.id
        }

        $Body = @{}
        $Body.passphrase = $Passphrase
        $Body.nodes = $NodeIds
        $Body.rangeStart = Get-Date -Format o $RangeStart.ToUniversalTime()
        $Body.rangeEnd = Get-Date -Format o $RangeEnd.ToUniversalTime()

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Body $Body -ContentType "application/json" -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Deletes the previous log collection archive
    .DESCRIPTION
    Deletes the previous log collection archive
#>
function Global:Remove-SgwLogCollection {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/logs/collection"
        $Method = "DELETE"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Download log collection archive after procedure completes
    .DESCRIPTION
    Download log collection archive after procedure completes
#>
function Global:Get-SgwLogCollection {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $True,
                Position = 1,
                HelpMessage = "Path to store log collection in")][System.IO.DirectoryInfo]$Path
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/logs/collection"
        $Method = "GET"

        $LogStatus = Get-SgwLogs

        if ($LogStatus.inProgress) {
            Throw "Log Collection still in progress"
        }

        if ($LogStatus.error) {
            Throw "Log Collection encountered error $($LogStatus.error)"
        }

        if (!(Test-Path $Path)) {
            Throw "Path $Path does not exist!"
        }
        else {
            $OutFile = Join-Path -Path $Path -ChildPath $LogStatus.fileName
            Write-Host "Saving file to $OutFile"
        }

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck -OutFile $OutFile
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## metrics ##

<#
    .SYNOPSIS
    Retrieves the metric names
    .DESCRIPTION
    Retrieves the metric names
#>
function Global:Get-SgwMetricNames {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/metric-names"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Performs an instant metric query at a single point in time
    .DESCRIPTION
    Performs an instant metric query at a single point in time
#>
function Global:Get-SgwMetricQuery {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $True,
                Position = 1,
                HelpMessage = "Prometheus query string.")][String]$Query,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "Query start, default current time (date-time).")][DateTime]$Time,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "Timeout in seconds.")][Int]$Timeout = 120
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
            $Uri += "&time=$( Get-Date -Format o $Time.ToUniversalTime() )"
        }

        if ($Timeout) {
            $Uri += "&timeout=$( $Timeout )s"
        }


        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Metrics = $Response.Json.data.result | % { [PSCustomObject]@{ Metric = $_.metric.__name__; Instance = $_.metric.instance; Time = (ConvertFrom-UnixTimestamp -Unit Seconds -Timestamp $_.value[0]); Value = $_.value[1] } }

        Write-Output $Metrics
    }
}

# TODO: Implement metrics cmdlets

## ntp-servers ##

# complete as of API 2.1

<#
    .SYNOPSIS
    Lists configured external NTP servers
    .DESCRIPTION
    Lists configured external NTP servers
#>
function Global:Get-SgwNtpServers {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/ntp-servers"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Change the external NTP servers used by the grid
    .DESCRIPTION
    Change the external NTP servers used by the grid
#>
function Global:Update-SgwNtpServers {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale license.")][String[]]$Servers,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Passphrase.")][String]$Passphrase,
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/ntp-servers/update"
        $Method = "POST"

        $Body = @{ }
        $Body.passphrase = $Passphrase
        $Body.servers = $Servers

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## objects ##


<#
    .SYNOPSIS
    Retrieves metadata for an object
    .DESCRIPTION
    Retrieves metadata for an object
#>
function Global:Get-SgwObjectMetadata {
    [CmdletBinding(DefaultParameterSetName="objectid")]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $True,
                ParameterSetName="objectid",
                Position = 1,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Object ID (e.g. S3 bucket/key or Swift container/object).")][String]$ObjectId,
        [parameter(Mandatory = $True,
                ParameterSetName="ContainerAndKey",
                Position = 1,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "S3 Bucket or Swift Container name.")][Alias("Bucket","BucketName","ContainerName")][String]$Container,
        [parameter(Mandatory = $True,
                ParameterSetName="ContainerAndKey",
                Position = 2,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "S3 Object Key or Swift Object Name.")][Alias("Key","Name")][String]$Object,
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "Maximum number of segements to return.")][Int]$MaxSegments
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/object-metadata"
        $Method = "POST"

        $Body = @{}
        if ($Container) {
            $ObjectId = "$Container/$Object"
        }
        $Body.objectId = $ObjectId
        if ($MaxSegments) {
            $Body.maxSegments = $MaxSegments
        }

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Body $Body -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## recovery ##

# complete as of API 2.1

<#
    .SYNOPSIS
    Lists grid nodes not connected to the grid
    .DESCRIPTION
    Lists grid nodes not connected to the grid
#>
function Global:Get-SgwRecoveryAvailableNodes {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/recovery/available-nodes"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Resets the recovery procedure to the not-started state
    .DESCRIPTION
    Resets the recovery procedure to the not-started state
#>
function Global:Reset-SgwRecovery {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/recovery"
        $Method = "DELETE"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Gets the recovery status
    .DESCRIPTION
    Gets the recovery status
#>
function Global:Get-SgwRecovery {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/recovery"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Starts the recovery procedure, retrieves configuration file and installs software
    .DESCRIPTION
    Starts the recovery procedure, retrieves configuration file and installs software
#>
function Global:Start-SgwRecovery {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $True,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Passphrase.")][String]$Passphrase,
        [parameter(Mandatory = $True,
                Position = 2,
                HelpMessage = "StorageGRID Node OID to recover.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Oid,
        [parameter(Mandatory = $True,
                Position = 3,
                HelpMessage = "StorageGRID Node Name to recover.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Name,
        [parameter(Mandatory = $True,
                Position = 4,
                HelpMessage = "StorageGRID Node IP to recover.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$Ip,
        [parameter(Mandatory = $True,
                Position = 5,
                HelpMessage = "Node to replace failed node.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][PSCustomObject]$ReplacementNode
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/recovery"
        $Method = "POST"

        $Body = @{}
        $Body.id = $ReplacementNode.Id
        $Body.ip = $Ip
        $Body.name = $Name
        $Body.oid = $Oid
        $Body.passphrase = $Passphrase

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Body $Body -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## recovery-package ##

<#
    .SYNOPSIS
    Retrieves the log collection procedure status
    .DESCRIPTION
    Retrieves the log collection procedure status
#>
function Global:Get-SgwRecoveryPackage {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $True,
                Position = 1,
                HelpMessage = "StorageGRID Webscale Passphrase.")][String]$Passphrase,
        [parameter(Mandatory = $True,
                Position = 1,
                HelpMessage = "Path to store log collection in")][System.IO.DirectoryInfo]$Path
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/recovery-package"
        $Method = "POST"

        if (!(Test-Path $Path)) {
            Throw "Path $Path does not exist!"
        }

        $Body = @{}
        $Body.passphrase = $Passphrase

        $Body = ConvertTo-Json -InputObject $Body

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Body $Body -Headers $Server.Headers -OutFile $Path -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }
    }
}

## regions ##

<#
    .SYNOPSIS
    Lists configured regions
    .DESCRIPTION
    Lists configured regions
#>
function Global:Get-SgwRegions {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/regions"
        $Method = "GET"

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

<#
    .SYNOPSIS
    Change the regions used by the grid
    .DESCRIPTION
    Change the regions used by the grid
#>
function Global:Update-SgwRegions {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "Regions.")][String[]]$Regions
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if ($Server.AccountId) {
            Throw "Operation not supported when connected as tenant. Use Connect-SgwServer without the AccountId parameter to connect as grid administrator and then rerun this command."
        }
    }

    Process {
        $Uri = $Server.BaseURI + "/grid/regions"
        $Method = "PUT"

        if (!$Regions.Contains("us-east-1")) {
            # us-east-1 must always be included in list of regions
            $Regions += "us-east-1"
        }

        $Body = ConvertTo-Json -InputObject $Regions

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Body $Body -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

## server-certificate ##

# TODO: Implement server-certificate Cmdlets

## users ##

<#
    .SYNOPSIS
    Retrieve all StorageGRID Users
    .DESCRIPTION
    Retrieve all StorageGRID Users
#>
function Global:Get-SgwUsers {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(Mandatory = $False,
                Position = 1,
                HelpMessage = "User type (default local).")][ValidateSet("local", "federated")][String]$Type = "local",
        [parameter(Mandatory = $False,
                Position = 2,
                HelpMessage = "Maximum number of results.")][Int]$Limit = 0,
        [parameter(Mandatory = $False,
                Position = 3,
                HelpMessage = "Pagination offset (value is Account's id).")][String]$Marker,
        [parameter(Mandatory = $False,
                Position = 4,
                HelpMessage = "if set, the marker element is also returned.")][Switch]$IncludeMarker,
        [parameter(Mandatory = $False,
                Position = 5,
                HelpMessage = "pagination order (desc requires marker).")][ValidateSet("asc", "desc")][String]$Order = "asc"
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
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
        if ($Type) {
            $Query += "&type=$Type"
        }
        if ($Marker) {
            $Query += "&marker=$Marker"
        }
        if ($IncludeMarker) {
            $Query += "&includeMarker=true"
        }
        if ($Order) {
            $Query += "&order=$Order"
        }

        $Uri += $Query

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Write-Error "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $( $responseBody.message )"
            return
        }

        $Response.Json.data | Add-Member -MemberType AliasProperty -Name userId -Value id

        Write-Output $Response.Json.data

        if ($Limit -eq 0 -and $Response.Json.data.count -eq 25) {
            Get-SgwAccounts -Server $Server -Limit $Limit -Marker ($Response.Json.data | select -last 1 -ExpandProperty id) -IncludeMarker:$IncludeMarker -Order $Order
        }
    }
}

# TODO: Implement users Cmdlets

## s3 ##

Set-Alias -Name Get-SgwAccountS3AccessKeys -Value Get-SgwS3AccessKeys
<#
    .SYNOPSIS
    Retrieve StorageGRID Webscale Account S3 Access Keys
    .DESCRIPTION
    Retrieve StorageGRID Webscale Account S3 Access Keys
#>
function Global:Get-SgwS3AccessKeys {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                ParameterSetName = "account",
                HelpMessage = "ID of a StorageGRID Webscale Account to get S3 Access Keys for.",
                ValueFromPipelineByPropertyName = $True)][String]$AccountId,
        [parameter(
                Mandatory = $False,
                Position = 1,
                ParameterSetName = "user",
                HelpMessage = "ID of a StorageGRID Webscale User.",
                ValueFromPipelineByPropertyName = $True)][Alias("userUUID")][String]$UserId,
        [parameter(
                Mandatory = $False,
                Position = 2,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if (!$Server.AccountId -and !$Server.SupportedApiVersions.Contains(1)) {
            Throw "This cmdlet requires API Version 1 support if connection to server was not made with a tenant account id. Either use Connect-SgwServer with the AccountId parameter or enable API version 1 with Update-SgwConfigManagement -MinApiVersion 1"
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }
        Write-Output $Response.Json.data
    }
}

Set-Alias -Name Get-SgwAccountS3AccessKey -Value Get-SgwS3AccessKey
<#
    .SYNOPSIS
    Retrieve a StorageGRID Webscale Account S3 Access Key
    .DESCRIPTION
    Retrieve a StorageGRID Webscale Account S3 Access Key
#>
function Global:Get-SgwS3AccessKey {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "ID of a StorageGRID Webscale Account to get S3 Access Keys for",
                ParameterSetName = "account",
                ValueFromPipelineByPropertyName = $True)][String]$AccountId,
        [parameter(
                Mandatory = $False,
                Position = 1,
                HelpMessage = "ID of a StorageGRID Webscale User.",
                ParameterSetName = "user",
                ValueFromPipelineByPropertyName = $True)][Alias("userUUID")][String]$UserId,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "Access Key to retrieve.",
                ValueFromPipelineByPropertyName = $True)][Alias("id")][String]$AccessKey,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if (!$Server.AccountId -and !$Server.SupportedApiVersions.Contains(1)) {
            Throw "This cmdlet requires API Version 1 support if connection to server was not made with a tenant account id. Either use Connect-SgwServer with the AccountId parameter or enable API version 1 with Update-SgwConfigManagement -MinApiVersion 1"
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        Write-Output $Response.Json.data
    }
}

Set-Alias -Name New-SgwAccountS3AccessKey -Value New-SgwS3AccessKey
<#
    .SYNOPSIS
    Create a new StorageGRID Webscale Account S3 Access Key
    .DESCRIPTION
    Create a new StorageGRID Webscale Account S3 Access Key
#>
function Global:New-SgwS3AccessKey {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory = $False,
                Position = 1,
                ParameterSetName = "account",
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Id of the StorageGRID Webscale Account to create new S3 Access Key for.")][String]$AccountId,
        [parameter(
                Mandatory = $False,
                Position = 2,
                ParameterSetName = "user",
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "ID of a StorageGRID Webscale User.")][Alias("userUUID")][String]$UserId,
        [parameter(
                Mandatory = $False,
                Position = 3,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Expiration date of the S3 Access Key.")][DateTime]$Expires
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if (!$Server.AccountId -and !$Server.SupportedApiVersions.Contains(1)) {
            Throw "This cmdlet requires API Version 1 support if connection to server was not made with a tenant account id. Either use Connect-SgwServer with the AccountId parameter or enable API version 1 with Update-SgwConfigManagement -MinApiVersion 1"
        }
        if ($Expires) {
            $ExpirationDate = Get-Date -Format o $Expires.ToUniversalTime()
        }
    }

    Process {
        if ($Server.AccountId) {
            $AccountId = $Server.AccountId
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
            $Body = ConvertTo-Json -InputObject @{ "expires" = "$ExpirationDate" }
        }

        try {
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -Body $Body -ContentType "application/json" -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $AccessKey = $Response.Json.data

        if (!$AccessKey) {
            Throw "Server did not return access key!"
        }

        Write-Verbose "Access Key response: $AccessKey"

        if (!$Server.AccessKeyStore[$AccountId]) {
            $Server.AccessKeyStore[$AccountId] = New-Object System.Collections.ArrayList
        }
        $Server.AccessKeyStore[$AccountId].Add($AccessKey)

        Write-Output $AccessKey
    }
}

Set-Alias -Name Remove-SgwAccountS3AccessKey -Value Remove-SgwS3AccessKey
<#
    .SYNOPSIS
    Delete a StorageGRID Webscale Account S3 Access Key
    .DESCRIPTION
    Delete a StorageGRID Webscale Account S3 Access Key
#>
function Global:Remove-SgwS3AccessKey {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "Id of the StorageGRID Webscale Account to delete S3 Access Key for.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][String]$AccountId,
        [parameter(
                Mandatory = $False,
                Position = 1,
                HelpMessage = "ID of a StorageGRID Webscale User.",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("userUUID")][String]$UserId,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "S3 Access Key ID to be deleted,",
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][Alias("id")][String]$AccessKey,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }
        if (!$Server.AccountId -and !$Server.SupportedApiVersions.Contains(1)) {
            Throw "This cmdlet requires API Version 1 support if connection to server was not made with a tenant account id. Either use Connect-SgwServer with the AccountId parameter or enable API version 1 with Update-SgwConfigManagement -MinApiVersion 1"
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
            $Response = Invoke-SgwRequest -WebSession $Server.Session -Method $Method -Uri $Uri -Headers $Server.Headers -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        if ($Server.AccessKeyStore[$AccountId].id -match $AccessKey -or $Server.AccessKeyStore[$AccountId].accessKey -match $AccessKey) {
            $Server.AccessKeyStore[$AccountId].Remove(($Server.AccessKeyStore[$AccountId] | Where-Object { $_.id -match $AccessKey -or $_.accessKey -match $AccessKey } | Select-Object -First 1))
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
function Global:Get-SgwReport {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory = $True,
                Position = 1,
                HelpMessage = "Attribut to report")][String][ValidateSet("Archive Nodes Installed (XANI)", "Archive Nodes Readable (XANR)", "Archive Nodes Writable (XANW)", "Awaiting - All (XQUZ)", "Awaiting - Client (XCQZ)", "Awaiting - Evaluation Rate (XEVT)", "CDMI - Ingested Bytes (XCRX) [Bytes]", "CDMI - Retrieved Bytes (XCTX) [Bytes]", "CDMI Ingest - Rate (XCIR) [MB/s]", "CDMI Operations - Failed (XCFA)", "CDMI Operations - Rate (XCRA) [Objects/s]", "CDMI Operations - Successful (XCSU)", "CDMI Retrieval - Rate (XCRR) [MB/s]", "Current ILM Activity (IQSZ)", "Installed Storage Capacity (XISC) [Bytes]", "Percentage Storage Capacity Used (PSCU)", "Percentage Usable Storage Capacity (PSCA)", "S3 - Ingested Bytes (XSRX) [Bytes]", "S3 - Retrieved Bytes (XSTX) [Bytes]", "S3 Ingest - Rate (XSIR) [MB/s]", "S3 Operations - Failed (XSFA)", "S3 Operations - Rate (XSRA) [Objects/s]", "S3 Operations - Successful (XSSU)", "S3 Operations - Unauthorized (XSUA)", "S3 Retrieval - Rate (XSRR) [MB/s]", "Scan Period - Estimated (XSCM) [us]", "Scan Rate (XSCT) [Objects/s]", "Storage Nodes Installed (XSNI)", "Storage Nodes Readable (XSNR)", "Storage Nodes Writable (XSNW)", "Swift - Ingested Bytes (XWRX) [Bytes]", "Swift - Retrieved Bytes (XWTX) [Bytes]", "Swift Ingest - Rate (XWIR) [MB/s]", "Swift Operations - Failed (XWFA)", "Swift Operations - Rate (XWRA) [Objects/s]", "Swift Operations - Successful (XWSU)", "Swift Operations - Unauthorized (XWUA)", "Swift Retrieval - Rate (XWRR) [MB/s]", "Total EC Objects (XECT)", "Total EC Reads - Failed (XERF)", "Total EC Reads - Successful (XERC)", "Total EC Writes - Failed (XEWF)", "Total EC Writes - Successful (XEWC)", "Total Objects Archived (XANO)", "Total Objects Deleted (XANP)", "Total Size of Archived Objects (XSAO)", "Total Size of Deleted Objects (XSAP)", "Usable Storage Capacity (XASC) [Bytes]", "Used Storage Capacity (XUSC) [Bytes]", "Used Storage Capacity for Data (XUSD) [Bytes]", "Used Storage Capacity for Metadata (XUDC) [Bytes]")]$Attribute,
        [parameter(
                Mandatory = $False,
                Position = 1,
                ParameterSetName = "oid",
                HelpMessage = "Topology OID to create report for")][String]$OID,
        [parameter(
                Mandatory = $False,
                Position = 1,
                ParameterSetName = "site",
                HelpMessage = "Site to create report for")][String]$Site,
        [parameter(
                Mandatory = $False,
                Position = 1,
                ParameterSetName = "node",
                HelpMessage = "Node to create report for")][String]$Node,
        [parameter(
                Mandatory = $False,
                Position = 2,
                HelpMessage = "Start Time (default: last hour)")][DateTime]$StartTime = (Get-Date).AddHours(-1),
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "End Time (default: current time)")][DateTime]$EndTime = (Get-Date)
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Server) {
            Throw "No StorageGRID Webscale Management Server management server found. Please run Connect-SgwServer to continue."
        }

        if ($Server.ApiVersion -lt 2.1) {
            Write-Warning "This Cmdlet uses an internal, undocumented API to retrieve the reports. Consider upgrading to StorageGRID 11.0 and use Get-SgwMetricQuery instead."
        }
        else {
            Write-Warning "This Cmdlet uses an internal, undocumented, legacy API to retrieve the reports. Use Get-SgwMetricQuery instead."
        }
    }

    Process {
        $StartTimeString = $StartTime.ToUniversalTime() | Get-Date -UFormat "%Y%m%d%H%M%S"
        $EndTimeString = $EndTime.ToUniversalTime() | Get-Date -UFormat "%Y%m%d%H%M%S"

        $AttributeCode = $Attribute -replace ".*\((.+)\).*", '$1'

        if (!$OID) {
            $Topology = Get-SgwTopologyHealth -Server $Server
            if ($Node) {
                $OID = $Topology.children.children | Where-Object { $_.name -eq $node } | Select-Object -First 1 -ExpandProperty oid
            }
            elseif ($Site) {
                $OID = $Topology.children | Where-Object { $_.name -eq $site } | Select-Object -First 1 -ExpandProperty oid
            }
            else {
                $OID = $Topology.oid
            }
        }

        $Method = "GET"
        $Uri = "https://$( $Server.Name )/NMS/render/JSP/DoXML.jsp?requestType=RPTX&mode=PAGE&start=$StartTimeString&end=$EndTimeString&attr=$AttributeCode&attrIndex=1&oid=$OID&type=text"

        try {
            $Response = Invoke-SgwRequest -Method $Method -WebSession $Server.Session -Headers $Server.Headers -Uri $Uri -SkipCertificateCheck:$Server.SkipCertificateCheck
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Throw "$Method to $Uri failed with Exception $( $_.Exception.Message ) `n $responseBody"
        }

        $Body = ($Response -split "`n" | ? { $_ -match "<body" })
        Write-Verbose "Body: $Body"

        if ($Response -match "Aggregate Time") {
            $Report = $Body -replace "<body.*Aggregate Time.*Type<br>", "" -split "<br>" -replace "([^,]+),[^,]+,([^ ]+) ([^,]*),([^ ]+) ([^,]*),([^ ]+) ([^,]*),.+", '$1;$2;$4;$6' | ? { $_ }
            foreach ($Line in $Report) {
                $Time, $Average, $Minimum, $Maximum = $Line -split ';'
                $Average = $Average -replace ",", "" -replace " ", ""
                $Minimum = $Minimum -replace ",", "" -replace " ", ""
                $Maximum = $Maximum -replace ",", "" -replace " ", ""
                [PSCustomObject]@{ "Time Received" = [DateTime]$time; "Average $Attribute" = $Average; "Minimum $Attribute" = $Minimum; "Maximum $Attribute" = $Maximum }
            }
        }
        elseif ($Response -match "Time Received") {
            $Report = $Body -replace "<body.*Time Received.*Type<br>", "" -split "<br>" -replace "([^,]+),[^,]+,[^,]+,[^,]+,([^ ]+) ([^,]*),.+", '$1;$2' | ? { $_ }
            foreach ($Line in $Report) {
                $Time, $Value = $Line -split ';'
                $Value = $Value -replace ",", "" -replace " ", ""
                [PSCustomObject]@{ "Time Received" = [DateTime]$time; $Attribute = $value }
            }
        }
        else {
            Write-Error "Cannot parse report output"
        }
    }
}

### workflows ###

<#
    .SYNOPSIS
    Merge two StorageGRIDs
    .DESCRIPTION
    Merge two StorageGRIDs
#>
function Global:Merge-SgwGrids {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "Source StorageGRID Webscale Management Server object")][PSCustomObject]$SourceServer,
        [parameter(
                Mandatory = $True,
                Position = 1,
                HelpMessage = "Destination StorageGRID Webscale Management Server object")][PSCustomObject]$DestinationServer,
        [parameter(
                Mandatory = $True,
                Position = 2,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Tenant root password (must be at least 8 characters).")][ValidateLength(8, 256)][String]$Password,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun
    )

    Process {
        Write-Information "Retrieving tenant accounts from source"
        $SourceAccounts = Get-SgwAccounts -Server $SourceServer
        Write-Information "Retrieving tenant accounts from destination"
        $DestinationAccounts = Get-SgwAccounts -Server $DestinationServer
        $DuplicateAccounts = $SourceAccounts  | Where-Object { $DestinationAccounts.Name -contains $_.Name }
        if ($DuplicateAccounts) {
            Write-Warning  "$( $DuplicateAccounts.Count ) duplicate accounts were found"
            if (!$DryRun) {
                $DuplicateAccountChoice = $Host.UI.PromptForChoice("Duplicate accounts",
                        "Continue with reusing existing accounts?",
                        @("&Yes", "&No"),
                        1)
                if ($DuplicateAccountChoice -eq 1) {
                    break
                }
            }
        }

        $SourceAccountsWithoutS3Capabilities = $SourceAccounts | Where-Object { !$_.capabilities.contains("s3") }
        $SourceAccountsWithS3Capabilities = $SourceAccounts | Where-Object { $_.capabilities.contains("s3") }
        $DestinationAccountsWithS3Capabilities = $DestinationAccounts | Where-Object { $_.capabilities.contains("s3") }

        if ($SourceAccountsWithoutS3Capabilities) {
            Write-Warning "$( $SourceAccountsWithoutS3Capabilities.Count ) accounts without S3 capability found which cannot be migrated"
            if (!$DryRun) {
                $NonS3AccountChoice = $Host.UI.PromptForChoice("Non-S3 accounts",
                        "Continue without transitioning non S3-Accounts?",
                        @("&Yes", "&No"),
                        1)
                if ($NonS3AccountChoice -eq 1) {
                    break
                }
            }
        }

        $SourceBuckets = $SourceAccounts | Get-SgwAccountUsage -Server $SourceServer | Select -ExpandProperty Buckets
        $DestinationBuckets = $SourceAccounts | Get-SgwAccountUsage -Server $SourceServer | Select -ExpandProperty Buckets

        $DuplicateBuckets = @()
        foreach ($SourceBucket in $SourceBuckets) {
            $DuplicateBuckets += $DestinationBuckets | Where-Object { $_.Name -ceq $SourceBucket.Name }
        }

        if ($DuplicateBuckets) {
            if (!$DryRun) {
                Throw "Source and destination contain the following duplicate buckets. Remove any duplicate buckets on source or destination before proceeding. Duplicate Buckets:`n$( $DuplicateBuckets.Name -join "`n" )"
            }
            else {
                Write-Warning "Source and destination contain the following duplicate buckets. Remove any duplicate buckets on source or destination before proceeding. Duplicate Buckets:`n$( $DuplicateBuckets.Name -join "`n" )"
            }
        }

        if (!$DryRun) {
            $ResetPasswordChoice = $Host.UI.PromptForChoice("Reset password",
                    "To configure replication on the source accounts, the root password needs to be reset to the provided password. Continue?",
                    @("&Yes", "&No"),
                    1)
            if ($ResetPasswordChoice -eq 1) {
                break
            }
        }

        $SourceAccountsWithS3Capabilities | Copy-SgwAccount -SourceServer $SourceServer -DestinationServer $DestinationServer -DryRun:$DryRun
    }
}

<#
    .SYNOPSIS
    Merge two StorageGRIDs
    .DESCRIPTION
    Merge two StorageGRIDs
#>
function Global:Copy-SgwAccount {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "Source StorageGRID Webscale Management Server object")][PSCustomObject]$SourceServer,
        [parameter(
                Mandatory = $True,
                Position = 1,
                HelpMessage = "Destination StorageGRID Webscale Management Server object")][PSCustomObject]$DestinationServer,
        [parameter(
                Mandatory = $True,
                Position = 2,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Source StorageGRID Webscale Management Account")][PSCustomObject]$AccountId,
        [parameter(
                Mandatory = $True,
                Position = 3,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "Tenant root password (must be at least 8 characters).")][ValidateLength(8, 256)][String]$Password,
        [parameter(
                Mandatory = $False,
                Position = 4,
                HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun
    )

    Process {
        $AccountCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "root", ($Password | ConvertTo-SecureString -AsPlainText -Force)

        $SourceAccount = Get-SgwAccount -Server $SourceServer -id $AccountId

        Write-Information "Resetting root password of account $( $SourceAccount.Name ) on source server"
        if (!$DryRun) {
            $SourceAccount | Update-SgwPassword -Server $SourceServer -id $AccountId -NewPassword
        }

        Write-Information "Logging in as root to account $( $SourceAccount.Name ) on source server"
        if (!$DryRun) {
            $SourceServer = $SourceServer | Connect-SgwServer -Credential $AccountCredential -AccountId $AccountId -Transient
        }

        Write-Information "Retrieving all buckets from source account"
        if (!$DryRun) {
            $SourceBuckets = Get-S3Buckets -Server $SourceServer -AccountId $AccountId
        }

        Write-Information "Creating account $( $SourceAccount.Name ) on destination server"
        if (!$DryRun) {
            $DestinationAccount = $SourceAccount | New-SgwAccount -Server $DestinationServer -Password $Password
        }

        Write-Information "Logging in as root to account $( $SourceAccount.Name ) on destination server"
        if (!$DryRun) {
            $DestinationServer = $DestinationServer | Connect-SgwServer -Credential $AccountCredential -Transient
        }

        Write-Information "Creating local group CopyGroup in account $( $SourceAccount.Name ) on destination server"
        if (!$DryRun) {
            New-SgwGroup -Server $DestinationServer -DisplayName "Temporary Group for Data Replication" -UniqueName "DataReplication" -rootAcces $true -S3FullAccess
        }

        Write-Information "Generating S3 Access Key on destination for Bucket replication"
        if (!$DryRun) {
            $DestinationAccessKey = New-SgwS3AccessKey -Server $DestinationServer
        }

        if (!$DryRun) {
            foreach ($SourceBucket in $SourceBuckets) {
                Copy-S3Bucket -SourceServer $SourceServer -DestinationServer $DestinationServer -Bucket $SourceBucket
            }
        }
    }
}

<#
    .SYNOPSIS
    Copy an S3 Bucket including all properties and data
    .DESCRIPTION
    Copy an S3 Bucket including all properties and data
#>
function Global:Copy-SgwBucket {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
                Mandatory = $True,
                Position = 0,
                HelpMessage = "Source StorageGRID Webscale Management Server object")][PSCustomObject]$SourceServer,
        [parameter(
                Mandatory = $True,
                Position = 1,
                HelpMessage = "Destination StorageGRID Webscale Management Server object")][PSCustomObject]$DestinationServer,
        [parameter(
                Mandatory = $True,
                Position = 2,
                HelpMessage = "Bucket Name")][PSCustomObject]$Bucket,
        [parameter(
                Mandatory = $False,
                Position = 3,
                HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun
    )

    Begin {
        if (!$SourceServer.AccountId) {
            Throw "Source server is not connected to account"
        }
        if (!$DestinationServer.AccountId) {
            Throw "Destination server is not connected to account"
        }
    }

    Process {
        Write-Information "Creating bucket $( $Bucket.Name ) on destination"
        if (!$DryRun) {
            New-S3Bucket -Server $DestinationServer -Name $Bucket.Name -Region $Bucket.Region
            # TODO: Copy other bucket properties such as ACLs from source bucket to destination bucket!
        }

        Write-Information "Adding endpoint configuration for bucket $( $Bucket.Name ) on source"
        if (!$DryRun) {
            New-SgwEndpoint -Server $SourceServer -DisplayName $Bucket.Name -EndpointUri $DestinationServerS3EndpointUrl -EndpointUrn "urn:sgws:s3:::$( $Bucket.Name )" -SkipCertificateCheck $DestinationServer.SkipCertificateCheck -AccessKey $AccessKey.AccessKey -SecretAccessKey $AccessKey.SecretAccessKey
        }

        Write-Information "Enable Bucket replication for bucket $( $Bucket.Name ) on source"
        if (!$DryRun) {
            # TODO: Replace with S3 Cmdlet
            Add-SgwBucketReplicationRule -Server $SourceServer -Id $Bucket.Name -Bucket $Bucket.Name -DestinationBucket $Bucket.Name -Status Enabled
            $ReplicationStartDate = Get-Date
        }

        Write-Information "Copy all older objects on themselve to update their modification time and trigger replication"

        if (!$DryRun) {
            Get-S3Objects -Server $SourceServer -Bucket $Bucket.Name | ForEach-Object {
                if ($_.LastModified -lt $ReplicationStartDate.ToUniversalTime()) {
                    $Metadata = $_ | Get-S3ObjectMetadata | Select -ExpandProperty CustomMetadata
                    Copy-S3Object -Server $SourceServer -Region $_.Region -Bucket $_.Bucket $_.Key -SourceBucket $_.Bucket -SourceKey $_.SourceKey -MetadataDirective REPLACE -Metadata $Metadata
                }
            }
        }
    }
}
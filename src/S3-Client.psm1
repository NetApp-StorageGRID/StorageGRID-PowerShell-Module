$AWS_PROFILE_PATH = "$HOME/.aws/"
$AWS_CREDENTIALS_FILE = $AWS_PROFILE_PATH + "credentials"
$AWS_CONFIG_FILE = $AWS_PROFILE_PATH + "config"

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

    # Using .NET JSON Serializer as JSON serialization included in Invoke-RestMethod has a length restriction for JSON content
    Add-Type -AssemblyName System.Web.Extensions
    $global:javaScriptSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $global:javaScriptSerializer.MaxJsonLength = [System.Int32]::MaxValue
    $global:javaScriptSerializer.RecursionLimit = 99
}
else {
    # unfortunately AWS Authentication is not RFC-7232 compliant (it is using semicolons in the value) 
    # and PowerShell 6 enforces strict header verification by default
    # therefore disabling strict header verification until AWS fixed this
    $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipHeaderValidation",$true)
}

### Helper Functions ###

function ParseErrorForResponseBody($Error) {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if ($Error.Exception.Response) {  
            $Reader = New-Object System.IO.StreamReader($Error.Exception.Response.GetResponseStream())
            $Reader.BaseStream.Position = 0
            $Reader.DiscardBufferedData()
            $ResponseBody = $Reader.ReadToEnd()
            if ($ResponseBody.StartsWith('{')) {
                $ResponseBody = $ResponseBody | ConvertFrom-Json | ConvertTo-Json
            }
            return $ResponseBody
        }
    }
    else {
        return $Error.ErrorDetails.Message
    }
}

function ConvertTo-SortedDictionary($HashTable) {
    $SortedDictionary = New-Object 'System.Collections.Generic.SortedDictionary[string, string]'
    foreach ($Key in $HashTable.Keys) {
        $SortedDictionary[$Key]=$HashTable[$Key]
    }
    Write-Output $SortedDictionary
}

function Get-SignedString {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$True,
                    Position=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True,
                    HelpMessage="Key in Bytes.")][Byte[]]$Key,
        [parameter(Mandatory=$False,
                    Position=1,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True,
                    HelpMessage="Unit of timestamp.")][String]$Message="",
        [parameter(Mandatory=$False,
                    Position=2,
                    HelpMessage="Algorithm to use for signing.")][ValidateSet("SHA1","SHA256")][String]$Algorithm="SHA256"
    )

    PROCESS {
        if ($Algorithm -eq "SHA1") {
            $Signer = New-Object System.Security.Cryptography.HMACSHA1
        }
        else {
            $Signer = New-Object System.Security.Cryptography.HMACSHA256
        }

        $Signer.Key = $Key
        $Signer.ComputeHash([Text.Encoding]::UTF8.GetBytes($Message))
    }
}

function Sign($Key,$Message) {
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha.Key = $Key
    $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Message))
}

function GetSignatureKey($Key, $Date, $Region, $Service) {
    $SignedDate = sign ([Text.Encoding]::UTF8.GetBytes(('AWS4' + $Key).toCharArray())) $Date
    $SignedRegion = sign $SignedDate $Region
    $SignedService = sign $SignedRegion $Service
    sign $SignedService "aws4_request"
}

function ConvertFrom-AwsConfigFile {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="AWS Config File")][String]$AwsConfigFile
    )

    Process {
        if (!(Test-Path $AwsConfigFile)) {
            throw "Config file $AwsConfigFile does not exist!"
        }
        $Content = Get-Content -Path $AwsConfigFile -Raw
        # remove empty lines
        $Content = $Content -replace "(`n$)*",""
        # convert to JSON structure
        $Json = $Content  -replace "profile ","" -replace "`n([^\[])",',$1' -replace "\[","`"" -replace "],","`":{`"" -replace "\s*=\s*","`":`"" -replace ",","`",`"" -replace "`n","`"}," -replace "^","{" -replace "$","`"}}"
        # parse JSON to Hashtable

        if ($PSVersionTable.PSVersion.Major -lt 6) {
            $Parser = New-Object Web.Script.Serialization.JavaScriptSerializer
            $Parser.MaxJsonLength = $Json.length
            $Hashtable = $Parser.Deserialize($Json, [hashtable])
            Write-Output $Hashtable
        }
        else {
            $Hashtable = ConvertFrom-Json -InputObject $Json -AsHashtable
            Write-Output $Hashtable
        }
    }
}

function ConvertTo-AwsConfigFile {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Config to store in config file")][hashtable]$Config,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="AWS Config File")][String]$AwsConfigFile
    )

    Process {
        if (!(Test-Path $AwsConfigFile)) {
            New-Item -Path $AwsConfigFile -ItemType File -Force
        }
        $Output = ""
        foreach ($Key in $Config.Keys) {
            $Output += "[$Key]`n"
            foreach ($Value in $Config[$Key].Keys) {
                $Output += "$Value = $($Config[$Key][$Value])`n"
            }
        }
        $Output | Out-File -FilePath $AwsConfigFile -NoNewline
    }
}

### AWS Cmdlets ###

<#
    .SYNOPSIS
    Retrieve SHA256 Hash for Payload
    .DESCRIPTION
    Retrieve SHA256 Hash for Payload
#>
function Global:Get-AwsHash {
    [CmdletBinding(DefaultParameterSetName="string")]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            ParameterSetName="string",
            HelpMessage="String to hash")][String]$StringToHash="",
        [parameter(
            Mandatory=$True,
            Position=1,
            ParameterSetName="file",
            HelpMessage="File to hash")][System.IO.FileInfo]$FileToHash
    )
 
    Process {
        $Hasher = [System.Security.Cryptography.SHA256]::Create()

        if ($FileToHash) {
            $Hash = Get-FileHash -Algorithm SHA256 -Path $FileToHash | select -ExpandProperty Hash
        }
        else {
            $Hash = ([BitConverter]::ToString($Hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($StringToHash))) -replace '-','').ToLower()
        }

        Write-Output $Hash
    }
}

<#
    .SYNOPSIS
    Create AWS Authentication Signature Version 2 for Request
    .DESCRIPTION
    Create AWS Authentication Signature Version 2 for Request
#>
function Global:New-AwsSignatureV2 {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="Endpoint hostname and optional port")][String]$EndpointHost,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="HTTP Request Method")][ValidateSet("OPTIONS","GET","HEAD","PUT","DELETE","TRACE","CONNECT")][String]$HTTPRequestMethod="GET",
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="URI")][String]$Uri="/",
        [parameter(
            Mandatory=$False,
            Position=6,
            HelpMessage="Content MD5")][String]$ContentMD5="",
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Content Type")][String]$ContentType="",
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Date")][String]$DateTime,
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Headers")][Hashtable]$Headers=@{},
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="Bucket")][String]$Bucket,
        [parameter(
            Mandatory=$False,
            Position=11,
            HelpMessage="Query String (unencoded)")][String]$QueryString
    )
 
    Process {
        # this Cmdlet follows the steps outlined in https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html

        # initialization
        if (!$DateTime) {
            $DateTime = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")        
        }

        Write-Debug "Task 1: Constructing the CanonicalizedResource Element "

        $CanonicalizedResource = ""
        Write-Debug "1. Start with an empty string:`n$CanonicalizedResource"

        if ($Bucket -and $EndpointHost -match "^$Bucket") {
            $CanonicalizedResource += "/$Bucket"
            Write-Debug "2. Add the bucketname for virtual host style:`n$CanonicalizedResource" 
        }
        else {
            Write-Debug "2. Bucketname already part of Url for path style therefore skipping this step"
        }

        $CanonicalizedResource += $Uri
        Write-Debug "3. Append the path part of the un-decoded HTTP Request-URI, up-to but not including the query string:`n$CanonicalizedResource" 

        $CanonicalizedResource += $QueryString
        Write-Debug "4. Append the query string unencoded for signing:`n$CanonicalizedResource" 

        Write-Debug "Task 2: Constructing the CanonicalizedAmzHeaders Element"

        Write-Debug "1. Filter for all headers starting with x-amz"
        $AmzHeaders = $Headers.Clone()
        # remove all headers which do not start with x-amz
        $Headers.Keys | % { if ($_ -notmatch "x-amz") { $AmzHeaders.Remove($_) } }
        
        Write-Debug "2. Sort headers lexicographically"
        $SortedAmzHeaders = ConvertTo-SortedDictionary $AmzHeaders
        $CanonicalizedAmzHeaders = ($SortedAmzHeaders.GetEnumerator()  | % { "$($_.Key.toLower()):$($_.Value)" }) -join "`n"
        if ($CanonicalizedAmzHeaders) {
            $CanonicalizedAmzHeaders = $CanonicalizedAmzHeaders + "`n"
        }
        Write-Debug "3. CanonicalizedAmzHeaders headers:`n$CanonicalizedAmzHeaders"

        Write-Debug "Task 3: String to sign"

        $StringToSign = "$HTTPRequestMethod`n$ContentMD5`n$ContentType`n$DateTime`n$CanonicalizedAmzHeaders$CanonicalizedResource"

        Write-Debug "1. StringToSign:`n$StringToSign"

        Write-Debug "Task 4: Signature"

        $SignedString = Get-SignedString -Key ([Text.Encoding]::UTF8.GetBytes($SecretAccessKey)) -Message $StringToSign -Algorithm SHA1
        $Signature = [Convert]::ToBase64String($SignedString)

        Write-Debug "1. Signature:`n$Signature" 

        Write-Output $Signature
    }
}

<#
    .SYNOPSIS
    Create AWS Authentication Signature Version 4 for Request
    .DESCRIPTION
    Create AWS Authentication Signature Version 4 for Request
#>
function Global:New-AwsSignatureV4 {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="Endpoint hostname and optional port")][String]$EndpointHost,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="HTTP Request Method")][ValidateSet("OPTIONS","GET","HEAD","PUT","DELETE","TRACE","CONNECT")][String]$HTTPRequestMethod="GET",
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="URI")][String]$Uri="/",
        [parameter(
            Mandatory=$False,
            Position=5,
            HelpMessage="Canonical Query String")][String]$CanonicalQueryString,
        [parameter(
            Mandatory=$False,
            Position=6,
            HelpMessage="Date Time (yyyyMMddTHHmmssZ)")][String]$DateTime,
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Date String (yyyyMMdd)")][String]$DateString,
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Request payload hash")][String]$RequestPayloadHash,
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Region")][String]$Region="us-east-1",
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="Region")][String]$Service="s3",
        [parameter(
            Mandatory=$False,
            Position=11,
            HelpMessage="Headers")][Hashtable]$Headers=@{},
        [parameter(
            Mandatory=$False,
            Position=12,
            HelpMessage="Content type")][String]$ContentType
    )

    Process {
        # this Cmdlet follows the steps outlined in http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

        # initialization
        if (!$RequestPayloadHash) {
            $RequestPayloadHash = Get-AwsHash -StringToHash ""
        }
        if (!$DateTime) {
            $DateTime = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")        
        }
        if (!$DateString) {
            $DateString = [DateTime]::UtcNow.ToString('yyyyMMdd')
        }

        Write-Debug "Task 1: Create a Canonical Request for Signature Version 4"
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        Write-Debug "1. HTTP Request Method:`n$HTTPRequestMethod" 

        # only URL encode if service is not S3
        if ($Service -ne "s3" -and $Uri -ne "/") {
            $CanonicalURI = [System.Web.HttpUtility]::UrlEncode($Uri)
        }
        else {
            $CanonicalURI = $Uri
        }
        Write-Debug "2. Canonical URI:`n$CanonicalURI"

        Write-Debug "3. Canonical query string:`n$CanonicalQueryString"

        if (!$Headers["host"]) { $Headers["host"] = $EndpointHost }
        if (!$Headers["x-amz-date"]) { $Headers["x-amz-date"] = $DateTime }
        if (!$Headers["content-type"] -and $ContentType) { $Headers["content-type"] = $ContentType }
        $SortedHeaders = ConvertTo-SortedDictionary $Headers
        $CanonicalHeaders = (($SortedHeaders.GetEnumerator()  | % { "$($_.Key.toLower()):$($_.Value)" }) -join "`n") + "`n"
        Write-Debug "4. Canonical headers:`n$CanonicalHeaders"

        $SignedHeaders = $SortedHeaders.Keys -join ";"
        Write-Debug "5. Signed headers:`n$SignedHeaders"

        Write-Debug "6. Hashed Payload`n$RequestPayloadHash"

        $CanonicalRequest = "$HTTPRequestMethod`n$CanonicalURI`n$CanonicalQueryString`n$CanonicalHeaders`n$SignedHeaders`n$RequestPayloadHash"
        Write-Debug "7. CanonicalRequest:`n$CanonicalRequest"

        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $CanonicalRequestHash = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($CanonicalRequest))) -replace '-','').ToLower()
        Write-Debug "8. Canonical request hash:`n$CanonicalRequestHash"

        Write-Debug "Task 2: Create a String to Sign for Signature Version 4"
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html

        $AlgorithmDesignation = "AWS4-HMAC-SHA256"
        Write-Debug "1. Algorithm designation:`n$AlgorithmDesignation"

        Write-Debug "2. request date value, specified with ISO8601 basic format in the format YYYYMMDD'T'HHMMSS'Z:`n$DateTime"

        $CredentialScope = "$DateString/$Region/$Service/aws4_request"
        Write-Debug "3. Credential scope:`n$CredentialScope"

        Write-Debug "4. Canonical request hash:`n$CanonicalRequestHash"

        $StringToSign = "$AlgorithmDesignation`n$DateTime`n$CredentialScope`n$CanonicalRequestHash"
        Write-Debug "StringToSign:`n$StringToSign"

        Write-Debug "Task 3: Calculate the Signature for AWS Signature Version 4"
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

        $SigningKey = GetSignatureKey $SecretAccessKey $DateString $Region $Service
        Write-Debug "1. Signing Key:`n$([System.BitConverter]::ToString($SigningKey))"

        $Signature = ([BitConverter]::ToString((sign $SigningKey $StringToSign)) -replace '-','').ToLower()
        Write-Debug "2. Signature:`n$Signature"

        Write-Output $Signature
    }
}

<#
    .SYNOPSIS
    Invoke AWS Request
    .DESCRIPTION
    Invoke AWS Request
#>
function Global:Invoke-AwsRequest {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$True,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="Account ID")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="HTTP Request Method")][ValidateSet("OPTIONS","GET","HEAD","PUT","DELETE","TRACE","CONNECT")][String]$HTTPRequestMethod="GET",
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Endpoint URL")][String]$EndpointUrl,
         [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Skip SSL Certificate check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=5,
            HelpMessage="URI")][String]$Uri="/",
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Query String")][Hashtable]$Query,
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Request payload")][String]$RequestPayload="",
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Region")][String]$Region="us-east-1",
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="Region")][String]$Service="s3",
        [parameter(
            Mandatory=$False,
            Position=11,
            HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SingerType="AWS4",
        [parameter(
            Mandatory=$False,
            Position=12,
            HelpMessage="Headers")][Hashtable]$Headers=@{},
        [parameter(
            Mandatory=$False,
            Position=13,
            HelpMessage="Content type")][String]$ContentType,
        [parameter(
            Mandatory=$False,
            Position=14,
            HelpMessage="Path where output should be saved to")][String]$FilePath,
        [parameter(
            Mandatory=$False,
            Position=15,
            HelpMessage="Bucket name")][String]$Bucket,
        [parameter(
            Mandatory=$False,
            Position=16,
            HelpMessage="File to output result to")][System.IO.DirectoryInfo]$OutFile,
        [parameter(
            Mandatory=$False,
            Position=17,
            HelpMessage="File to read data from")][System.IO.FileInfo]$InFile
    )

    Begin {
        $Credential = $null
        # convenience method to autogenerate credentials
        Write-Verbose "Account ID: $AccountId"
        if ($CurrentSgwServer -and !$CurrentSgwServer.DisableAutomaticAccessKeyGeneration) {
            if (!$Profile -and !$AccessKey -and $CurrentSgwServer.AccountId -and ($EndpointUrl -or $CurrentSgwServer.S3EndpointUrl)) {
                Write-Verbose "No profile and no access key specified, but connected to a StorageGRID tenant. Therefore using autogenerated temporary AWS credentials"
                if ($CurrentSgwServer.AccessKeyStore[$CurrentSgwServer.AccountId].expires -ge (Get-Date).ToUniversalTime().AddMinutes(1) -or ($CurrentSgwServer.AccessKeyStore[$CurrentSgwServer.AccountId] -and !$CurrentSgwServer.AccessKeyStore[$CurrentSgwServer.AccountId].expires)) {
                    $Credential = $CurrentSgwServer.AccessKeyStore[$CurrentSgwServer.AccountId] | Sort-Object -Property expires | Select-Object -Last 1
                    Write-Verbose "Using existing Access Key $($Credential.AccessKey)"
                }
                else {
                    $Credential = New-SgwS3AccessKey -Expires (Get-Date).AddSeconds($CurrentSgwServer.TemporaryAccessKeyExpirationTime)
                    Write-Verbose "Created new temporary Access Key $($Credential.AccessKey)"
                }
            }
            elseif (!$Profile -and !$AccessKey -and $AccountId -and $CurrentSgwServer.SupportedApiVersions.Contains(1)) {
                Write-Verbose "No profile and no access key specified, but connected to a StorageGRID server. Therefore using autogenerated temporary AWS credentials for account ID $AccountId and removing them after command execution"
                if ($CurrentSgwServer.AccessKeyStore[$AccountId].expires -ge (Get-Date).ToUniversalTime().AddMinutes(1) -or ($CurrentSgwServer.AccessKeyStore[$AccountId] -and !$CurrentSgwServer.AccessKeyStore[$AccountId].expires)) {
                    $Credential = $CurrentSgwServer.AccessKeyStore[$AccountId] | Sort-Object -Property expires | Select-Object -Last 1
                    Write-Verbose "Using existing Access Key $($Credential.AccessKey)"
                }
                else {
                    $Credential = New-SgwS3AccessKey -AccountId $AccountId -Expires (Get-Date).AddSeconds($CurrentSgwServer.TemporaryAccessKeyExpirationTime)
                    Write-Verbose "Created new temporary Access Key $($Credential.AccessKey)"
                }
            }
            elseif (!$Profile -and !$AccessKey -and $Bucket -and $CurrentSgwServer.SupportedApiVersions.Contains(1) -and !$CurrentSgwServer.AccountId) {
                # need to check each account for its buckets to determine which account the bucket belongs to
                $AccountId = foreach ($Account in (Get-SgwAccounts)) {
                    if ($Account | Get-SgwAccountUsage | select -ExpandProperty buckets | ? { $_.name -eq $Bucket }) {
                        Write-Output $Account.id
                        break
                    }
                }
                if ($AccountId) {
                    Write-Verbose "No profile and no access key specified, therefore using autogenerated temporary AWS credentials and removing them after command execution"
                    if ($CurrentSgwServer.AccessKeyStore[$AccountId].expires -ge (Get-Date).ToUniversalTime().AddMinutes(1) -or ($CurrentSgwServer.AccessKeyStore[$AccountId] -and !$CurrentSgwServer.AccessKeyStore[$AccountId].expires)) {
                        $Credential = $CurrentSgwServer.AccessKeyStore[$AccountId] | Sort-Object -Property expires | Select-Object -Last 1
                        Write-Verbose "Using existing Access Key $($Credential.AccessKey)"
                    }
                    else {
                        $Credential = New-SgwS3AccessKey -AccountId $AccountId -Expires (Get-Date).AddSeconds($CurrentSgwServer.TemporaryAccessKeyExpirationTime)
                        Write-Verbose "Created new temporary Access Key $($Credential.AccessKey)"
                    }
                }
                else {
                    $Profile = "default"
                }
            }
            else {
                Write-Verbose "StorageGRID Server present, but either API Version 1 is not supported or no EndpointUrl available"
                $Profile = "default"            
            }

            if ($Credential -and !$EndpointUrl -and $CurrentSgwServer.S3EndpointUrl) {
                Write-Verbose "EndpointUrl not specified, but discovered S3 Endpoint $($CurrentSgwServer.S3EndpointUrl) from StorageGRID Server"
                $EndpointUrl = $CurrentSgwServer.S3EndpointUrl
                if ($CurrentSgwServer.SkipCertificateCheck) {
                    $SkipCertificateCheck = $True
                }
            }

            if ($Credential -and $EndpointUrl) {
                $AccessKey = $Credential.accessKey
                $SecretAccessKey = $Credential.secretAccessKey
            }
            elseif ($Credential) {
                $Profile = "default"
            }
        }

        if (!$Credential -and !$AccessKey -and !$Profile) {
            $Profile = "default"
        }
        
        if ($Profile -and !$AccessKey) {
            Write-Verbose "Using credentials from profile $Profile"
            if (!(Test-Path $AWS_CREDENTIALS_FILE)) {
                throw "Profile $Profile does not contain credentials. Either connect to a StorageGRID Server using Connect-SgwServer or add credentials to the default profile with Add-AwsCredentials"
            }
            $Credentials = ConvertFrom-AwsConfigFile -AwsConfigFile $AWS_CREDENTIALS_FILE
            $AccessKey = $Credentials[$Profile].aws_access_key_id
            $SecretAccessKey = $Credentials[$Profile].aws_secret_access_key
            if (Test-Path $AWS_CONFIG_FILE) {
                $Config = ConvertFrom-AwsConfigFile -AwsConfigFile $AWS_CONFIG_FILE
                if (!$Region) {
                    $Region = $Config[$Profile].region
                }
            }
        }

        if (!$AccessKey) {
            throw "No Access Key specified"
        }
        if (!$SecretAccessKey) {
            throw "No Secret Access Key specified"
        }

        # check if untrusted SSL certificates should be ignored
        if ($SkipCertificateCheck) {
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
            # currently there is no way to re-enable certificate check for the current session in PowerShell prior to version 6
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                if ("Invoke-RestMethod:SkipCertificateCheck") {
                    $PSDefaultParameterValues.Remove("Invoke-RestMethod:SkipCertificateCheck")
                }
            }
        }

        if ([environment]::OSVersion.Platform -match "Win") {
            # check if proxy is used
            $ProxyRegistry = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $ProxySettings = Get-ItemProperty -Path $ProxyRegistry
            if ($ProxySettings.ProxyEnable) {
                Write-Warning "Proxy Server $($ProxySettings.ProxyServer) configured in Internet Explorer may be used to connect to the endpoint!"
            }
            if ($ProxySettings.AutoConfigURL) {
                Write-Warning "Proxy Server defined in automatic proxy configuration script $($ProxySettings.AutoConfigURL) configured in Internet Explorer may be used to connect to the endpoint!"
            }
        }

        if (!$EndpointUrl) {
            if ($Region -eq "us-east-1") {
                $EndpointUrl = "https://s3.amazonaws.com"
            }
            else {
                $EndpointUrl = "https://s3.$Region.amazonaws.com"
            }
        }

        # remove port 80 and port 443 from EndpointUrl as they must not be included
        $EndpointUrl = $EndpointUrl -replace ':80$','' -replace ':443$',''

        # extract hostname and port from Endpoint URL for signing
        $EndpointHost = $EndpointUrl -replace '.*://',''
    }
 
    Process {        
        $DateTime = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
        $DateString = [DateTime]::UtcNow.ToString('yyyyMMdd')

        $QueryString = ""
        $CanonicalQueryString = ""
        if ($Query.Keys.Count -ge 1) {
            # using Sorted Dictionary as query need to be sorted by encoded keys
            $SortedQuery = New-Object 'System.Collections.Generic.SortedDictionary[string, string]'
            
            foreach ($Key in $Query.Keys) {
                # Key and value need to be URL encoded separately
                $SortedQuery[$Key]=$Query[$Key]
            }
            foreach ($Key in $SortedQuery.Keys) {
                # AWS V2 only requires specific queries to be included in signing process                
                if ($Key -match "versioning|location|acl|torrent|lifecycle|versionid|response-content-type|response-content-language|response-expires|response-cache-control|response-content-disposition|response-content-encoding") {
                    $QueryString += "$Key=$($SortedQuery[$Key])&"
                }
                $CanonicalQueryString += "$([System.Web.HttpUtility]::UrlEncode($Key))=$([System.Web.HttpUtility]::UrlEncode($SortedQuery[$Key]))&"
            }
            $QueryString = $QueryString -replace "&`$",""
            $CanonicalQueryString = $CanonicalQueryString -replace "&`$",""
        }

        if ($InFile) {
            $RequestPayloadHash=Get-AWSHash -FileToHash $InFile
        }
        else {
            $RequestPayloadHash=Get-AWSHash -StringToHash $RequestPayload
        }
        
        if (!$Headers["host"]) { $Headers["host"] = $EndpointHost }
        if (!$Headers["x-amz-content-sha256"]) { $Headers["x-amz-content-sha256"] = $RequestPayloadHash }
        if (!$Headers["x-amz-date"]) { $Headers["x-amz-date"] = $DateTime }
        if (!$Headers["content-type"] -and $ContentType) { $Headers["content-type"] = $ContentType }

        $SortedHeaders = ConvertTo-SortedDictionary $Headers

        $SignedHeaders = $SortedHeaders.Keys -join ";"

        if ($SingerType = "AWS4") {
            Write-Verbose "Using AWS Signature Version 4"
            $Signature = New-AwsSignatureV4 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointHost $EndpointHost -Uri $Uri -CanonicalQueryString $CanonicalQueryString -HTTPRequestMethod $HTTPRequestMethod -RequestPayloadHash $RequestPayloadHash -DateTime $DateTime -DateString $DateString -Headers $Headers
            Write-Debug "Task 4: Add the Signing Information to the Request"
            # http://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
            $Headers["Authorization"]="AWS4-HMAC-SHA256 Credential=$AccessKey/$DateString/$Region/$Service/aws4_request,SignedHeaders=$SignedHeaders,Signature=$Signature"
            Write-Debug "Headers:`n$(ConvertTo-Json -InputObject $Headers)"
        }
        else {
            Write-Verbose "Using AWS Signature Version 2"
            $Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointHost $EndpointHost -Uri $Uri -HTTPRequestMethod $HTTPRequestMethod -ContentMD5 $ContentMd5 -ContentType $ContentType -Date $DateTime -Bucket $Bucket -QueryString $QueryString
        }

        if ($CanonicalQueryString) {
            $Url = $EndpointUrl + $Uri + "?" + $CanonicalQueryString
        }
        else {
            $Url = $EndpointUrl + $Uri
        }

        try {            
            if ($RequestPayload) {
                if ($OutFile) {
                    Write-Verbose "RequestPayload:`n$RequestPayload"
                    Write-Verbose "Saving output in file $OutFile"
                    $Result = Invoke-RestMethod -Method $HTTPRequestMethod -Uri $Url -Headers $Headers -Body $RequestPayload -OutFile $OutFile
                }                
                else {
                    Write-Verbose "RequestPayload:`n$RequestPayload"
                    $Result = Invoke-RestMethod -Method $HTTPRequestMethod -Uri $Url -Headers $Headers -Body $RequestPayload
                }
            }
            else {
                if ($OutFile) {
                    Write-Verbose "Saving output in file $OutFile"
                    $Result = Invoke-RestMethod -Method $HTTPRequestMethod -Uri $Url -Headers $Headers -OutFile $OutFile
                }
                elseif ($InFile) {
                    Write-Verbose "InFile:`n$InFile"
                    $Result = Invoke-RestMethod -Method $HTTPRequestMethod -Uri $Url -Headers $Headers -InFile $InFile
                }
                else {
                    $Result = Invoke-RestMethod -Method $HTTPRequestMethod -Uri $Url -Headers $Headers
                }
            }
        }
        catch {
            $ResponseBody = ParseErrorForResponseBody $_
            Write-Error "$HTTPRequestMethod to $Url failed with Exception $($_.Exception.Message) `n $ResponseBody"
        }

        Write-Output $Result
    }
}

<#
    .SYNOPSIS
    Add AWS Credentials
    .DESCRIPTION
    Add AWS Credentials
#>
function Global:Add-AwsCredentials {
    [CmdletBinding(DefaultParameterSetName="credential")]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile="default",
        [parameter(
            ParameterSetName="credential",
            Mandatory=$True,
            Position=1,
            HelpMessage="Credential")][PSCredential]$Credential,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$True,
            Position=1,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$True,
            Position=2,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Custom endpoint URL if different than AWS URL")][String]$EndpointUrl
    )
 
    Process {
        $Credentials = ConvertFrom-AwsConfigFile -AwsConfigFile $AWS_CREDENTIALS_FILE
        $Credentials[$Profile] = @{}
        $Credentials[$Profile]["aws_access_key_id"] = $AccessKey
        $Credentials[$Profile]["aws_secret_access_key"] = $SecretAccessKey
    }
}

### S3 Cmdlets ###

## Buckets ##

<#
    .SYNOPSIS
    Get S3 Buckets
    .DESCRIPTION
    Get S3 Buckets
#>
function Global:Get-S3Buckets {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=1,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=2,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="AWS Profile to use which contains AWS credentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=2,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=3,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=2,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId
    )
 
    Process {
        $Uri = '/'
        $HTTPRequestMethod = "GET"

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
        }
        else {
            if ($CurrentSgwServer.SupportedApiVersions -match "1" -and !$CurrentSgwServer.AccountId) {
                Get-SgwAccounts -Capabilities "s3" |  Get-S3Buckets -EndpointUrl $EndpointUrl -SkipCertificateCheck:$SkipCertificateCheck
            }
            else {
                $Result = Invoke-AwsRequest -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
            }
        }
        if ($Result) {
            $Buckets = @()
            if ($Result.ListAllMyBucketsResult) {
                foreach ($Bucket in $Result.ListAllMyBucketsResult.Buckets.ChildNodes) {
                    $Buckets += [PSCustomObject]@{ Name = $Bucket.Name; CreationDate = $Bucket.CreationDate }
                }
                $Owner = [PSCustomObject]@{ ID = $Result.ListAllMyBucketsResult.Owner.ID; DisplayName = $Result.ListAllMyBucketsResult.Owner.DisplayName }
            }
            $Buckets | Add-Member -MemberType NoteProperty -Name OwnerId -Value $Owner.ID
            $Buckets | Add-Member -MemberType NoteProperty -Name OwnerDisplayName -Value $Owner.DisplayName
            Write-Output $Buckets
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket
    .DESCRIPTION
    Get S3 Bucket
#>
function Global:Get-S3Bucket {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][Alias("Name")][String]$Bucket,
        [parameter(
            Mandatory=$False,
            Position=6,
            HelpMessage="Maximum Number of keys to return")][Int][ValidateRange(0,1000)]$MaxKeys=0,
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Bucket prefix for filtering")][String]$Prefix,
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Bucket prefix for filtering")][String][ValidateLength(1,1)]$Delimiter,
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Return Owner information (Only valid for list type 2).")][Switch]$FetchOwner=$False,
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="Return key names after a specific object key in your key space. The S3 service lists objects in UTF-8 character encoding in lexicographical order (Only valid for list type 2).")][String]$StartAfter,
        [parameter(
            Mandatory=$False,
            Position=11,
            HelpMessage="Continuation token (Only valid for list type 1).")][String]$Marker,
       [parameter(
            Mandatory=$False,
            Position=12,
            HelpMessage="Continuation token (Only valid for list type 2).")][String]$ContinuationToken,
        [parameter(
            Mandatory=$False,
            Position=13,
            HelpMessage="Encoding type (Only allowed value is url).")][String][ValidateSet("url")]$EncodingType,
        [parameter(
            Mandatory=$False,
            Position=14,
            HelpMessage="Bucket list type.")][String][ValidateSet(1,2)]$ListType=1

    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }

        $HTTPRequestMethod = "GET"

        $Query = @{}

        if ($Delimiter) { $Query["delimiter"] = $Delimiter }
        if ($EncodingType) { $Query["encoding-type"] = $EncodingType }
        if ($MaxKeys -ge 1) {
            $Query["max-keys"] = $MaxKeys
        }
        if ($Prefix) { $Query["prefix"] = $Prefix }

        # S3 supports two types for listing buckets, but only v2 is recommended, thus using list-type=2 query parameter
        if ($ListType -eq 1) {
            if ($Marker) { $Query["marker"] = $Marker }
        }
        else {
            $Query["list-type"] = 2
            if ($FetchOwner) { $Query["fetch-owner"] = $FetchOwner }
            if ($StartAfter) { $Query["start-after"] = $StartAfter }
            if ($ContinuationToken) { $Query["continuation-token"] = $ContinuationToken }
        }

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }

        $Objects = $Result.ListBucketResult.Contents | ? { $_ }
        $Objects | Add-Member -MemberType NoteProperty -Name Bucket -Value $Result.ListBucketResult.Name

        Write-Output $Objects

        if ($Result.ListBucketResult.IsTruncated -eq "true" -and $MaxKeys -eq 0) {
            Write-Verbose "1000 Objects were returned and max keys was not limited so continuing to get all objects"
            Write-Debug "NextMarker: $($Result.ListBucketResult.NextMarker)"
            if ($Profile) {
                Get-S3Bucket -Profile $Profile -EndpointUrl $EndpointUrl -SkipCertificateCheck:$SkipCertificateCheck -UrlStyle $UrlStyle -Bucket $Bucket -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $Result.ListBucketResult.NextContinuationToken -Marker $Result.ListBucketResult.NextMarker
            }
            elseif ($AccessKey) {
                Get-S3Bucket -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl $EndpointUrl -SkipCertificateCheck:$SkipCertificateCheck -UrlStyle $UrlStyle -Bucket $Bucket -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $Result.ListBucketResult.NextContinuationToken -Marker $Result.ListBucketResult.NextMarker
            }
            elseif ($AccountId) {
                Get-S3Bucket -AccountId $AccountId -EndpointUrl $EndpointUrl -SkipCertificateCheck:$SkipCertificateCheck -UrlStyle $UrlStyle -Bucket $Bucket -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $Result.ListBucketResult.NextContinuationToken -Marker $Result.ListBucketResult.NextMarker
            }
            else {
                Get-S3Bucket -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl $EndpointUrl -SkipCertificateCheck:$SkipCertificateCheck -UrlStyle $UrlStyle -Bucket $Bucket -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $Result.ListBucketResult.NextContinuationToken -Marker $Result.ListBucketResult.NextMarker
            }            
        }   
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket
    .DESCRIPTION
    Get S3 Bucket
#>
function Global:New-S3Bucket {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][Alias("Name")][String]$Bucket,
        [parameter(
            Mandatory=$False,
            Position=6,
            HelpMessage="Canned ACL")][Alias("CannedAcl")][String][ValidateSet("private","public-read","public-read-write","aws-exec-read","authenticated-read","bucket-owner-read","bucket-owner-full-control")]$Acl,
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Canned ACL")][Alias("Location","LocationConstraint")][String]$Region

    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }

        $HTTPRequestMethod = "PUT"

        if ($Region) {
            $RequestPayload = "<CreateBucketConfiguration xmlns=`"http://s3.amazonaws.com/doc/2006-03-01/`"><LocationConstraint>$Region</LocationConstraint></CreateBucketConfiguration>"
        }

        $Query = @{}

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -RequestPayload $RequestPayload -Query $Query -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -RequestPayload $RequestPayload -Query $Query -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -RequestPayload $RequestPayload -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -RequestPayload $RequestPayload -Query $Query -ErrorAction Stop
        }

        Write-Output $Result
    }
}

<#
    .SYNOPSIS
    Remove S3 Bucket
    .DESCRIPTION
    Remove S3 Bucket
#>
function Global:Remove-S3Bucket {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][Alias("Name")][String]$Bucket

    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }

        $HTTPRequestMethod = "DELETE"

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
        }

        Write-Output $Result
    }
}

## Objects ##

Set-Alias -Name Get-S3Objects -Value Get-S3Bucket

Set-Alias -Name Get-S3Object -Value Read-S3Object
<#
    .SYNOPSIS
    Get S3 Bucket
    .DESCRIPTION
    Get S3 Bucket
#>
function Global:Read-S3Object {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][String]$Bucket,
        [parameter(
            Mandatory=$True,
            Position=6,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Object key")][Alias("Object","Name")][String]$Key,
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Byte range to retrieve from object")][String]$Range,
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Path where object should be stored")][Alias("OutFile")][System.IO.DirectoryInfo]$Path
    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }
        
        $Uri += $Key        

        $HTTPRequestMethod = "GET"

        $Headers = @{}
        if ($Range) {            
            $Headers["Range"] = $Range
        }

        if ($Path) {
            if ($Path.Exists) {
                $Item = Get-Item $Path
                if ($Item -is [FileInfo]) {
                    $OutFile = $Item
                }
                else {
                    $OutFile = Join-Path -Path $Path -ChildPath $Key
                }
            }
            elseif ($Path.Parent.Exists) {
                $OutFile = $Path
            }
            else {
                Throw "Path $Path does not exist and parent directory $($Path.Parent) also does not exist"
            }
        }

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Headers $Headers -OutFile $OutFile -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Headers $Headers -OutFile $OutFile -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Headers $Headers -OutFile $OutFile -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Headers $Headers -OutFile $OutFile -ErrorAction Stop
        }

        Write-Output $Result
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket
    .DESCRIPTION
    Get S3 Bucket
#>
function Global:Write-S3Object {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][String]$Bucket,
        [parameter(
            Mandatory=$False,
            Position=6,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Object key. If not provided, filename will be used")][Alias("Object","Name")][String]$Key,
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Path where object should be stored")][Alias("Path")][System.IO.FileInfo]$InFile
    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }

        if (!$InFile.Exists) {
            Throw "File $InFile does not exist"
        }

        if (!$Key) {
            $Key = $InFile.Name
        }
        
        $Uri += $Key        

        $HTTPRequestMethod = "PUT"

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -InFile $InFile -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -OutFile $InFile -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -InFile $InFile -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -InFile $InFile -ErrorAction Stop
        }

        Write-Output $Result
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket
    .DESCRIPTION
    Get S3 Bucket
#>
function Global:Remove-S3Object {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][String]$Bucket,
        [parameter(
            Mandatory=$True,
            Position=6,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Object key")][Alias("Object","Name")][String]$Key
    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }
        
        $Uri += $Key        

        $HTTPRequestMethod = "DELETE"

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Outfile $FilePath -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Outfile $FilePath -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Outfile $FilePath -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Outfile $FilePath -ErrorAction Stop
        }
    }
}

# StorageGRID specific #

<#
    .SYNOPSIS
    Get S3 Bucket Consistency Setting
    .DESCRIPTION
    Get S3 Bucket Consistency Setting
#>
function Global:Get-S3BucketConsistency {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][Alias("Name")][String]$Bucket
    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }

        $HTTPRequestMethod = "GET"

        $Query = @{"x-ntap-sg-consistency"=""}

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }

        $BucketConsistency = [PSCustomObject]@{Bucket=$Bucket;Consistency=$Result.Consistency.InnerText}

        Write-Output $BucketConsistency
    }
}

<#
    .SYNOPSIS
    Modify S3 Bucket Consistency Setting
    .DESCRIPTION
    Modify S3 Bucket Consistency Setting
#>
function Global:Update-S3BucketConsistency {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][Alias("Name")][String]$Bucket,
        [parameter(
            Mandatory=$True,
            Position=5,
            HelpMessage="Bucket")][ValidateSet("all","strong-global","strong-site","default","available","weak")][String]$Consistency
    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }

        $HTTPRequestMethod = "PUT"

        $Query = @{"x-ntap-sg-consistency"=$Consistency}

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket Storage Usage
    .DESCRIPTION
    Get S3 Bucket Storage Usage
#>
function Global:Get-S3StorageUsage {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck
    )
 
    Process {
        $Uri = "/"

        $HTTPRequestMethod = "GET"

        $Query = @{"x-ntap-sg-usage"=""}

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }

        $UsageResult = [PSCustomObject]@{CalculationTime=(Get-Date -Date $Result.UsageResult.CalculationTime);ObjectCount=$Result.UsageResult.ObjectCount;DataBytes=$Result.UsageResult.DataBytes;buckets=$Result.UsageResult.Buckets.ChildNodes}

        Write-Output $UsageResult
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket Last Access Time
    .DESCRIPTION
    Get S3 Bucket Last Access Time
#>
function Global:Get-S3BucketLastAccessTime {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
  
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][Alias("Name")][String]$Bucket
    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }

        $HTTPRequestMethod = "GET"

        $Query = @{"x-ntap-sg-lastaccesstime"=""}

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }

        $BucketLastAccessTime = [PSCustomObject]@{Bucket=$Bucket;LastAccessTime=$Result.LastAccessTime.InnerText}

        Write-Output $BucketLastAccessTime
    }
}

<#
    .SYNOPSIS
    Enable S3 Bucket Last Access Time
    .DESCRIPTION
    Enable S3 Bucket Last Access Time
#>
function Global:Enable-S3BucketLastAccessTime {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][Alias("Name")][String]$Bucket
    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }

        $HTTPRequestMethod = "PUT"

        $Query = @{"x-ntap-sg-lastaccesstime"="enabled"}

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
    }
}

<#
    .SYNOPSIS
    Disable S3 Bucket Last Access Time
    .DESCRIPTION
    Disable S3 Bucket Last Access Time
#>
function Global:Disable-S3BucketLastAccessTime {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName="keys",
            Mandatory=$False,
            Position=1,
            HelpMessage="S3 Secret Access Key")][String]$SecretAccessKey,
        [parameter(
            ParameterSetName="account",
            Mandatory=$False,
            Position=0,
            HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId,
        [parameter(
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="Path Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
            Mandatory=$True,
            Position=5,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket")][Alias("Name")][String]$Bucket
    )
 
    Process {
        if ($UrlStyle -eq "virtual-hosted") {
            Write-Verbose "Using virtual-hosted style URL"
            $Uri = "/"
            $Protocol = $EndpointUrl -replace '://.*','://'
            $EndpointHost  = $EndpointUrl -replace '(.+://)',''
            $EndpointUrl = $Protocol + $Bucket + '.' + $EndpointHost
        }
        else {
            Write-Verbose "Using path style URL"
            $Uri = "/$Bucket/"
        }

        $HTTPRequestMethod = "PUT"

        $Query = @{"x-ntap-sg-lastaccesstime"="disabled"}

        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccessKey) {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        elseif ($AccountId) {
            $Result = Invoke-AwsRequest -AccountId $AccountId -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -Bucket $Bucket -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
    }
}
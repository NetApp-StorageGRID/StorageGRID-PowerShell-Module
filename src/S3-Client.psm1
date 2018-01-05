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
}

# Using .NET JSON Serializer as JSON serialization included in Invoke-RestMethod has a length restriction for JSON content
Add-Type -AssemblyName System.Web.Extensions
$global:javaScriptSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$global:javaScriptSerializer.MaxJsonLength = [System.Int32]::MaxValue
$global:javaScriptSerializer.RecursionLimit = 99

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

function ConvertTo-SortedDictionary($HashTable) {
    $SortedDictionary = New-Object 'System.Collections.Generic.SortedDictionary[string, string]'
    foreach ($Key in $HashTable.Keys) {
        $SortedDictionary[$Key]=$HashTable[$Key]
    }
    Write-Output $SortedDictionary
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
        $Parser = New-Object Web.Script.Serialization.JavaScriptSerializer
        $Parser.MaxJsonLength = $Json.length
        $Hashtable = $Parser.Deserialize($Json, [hashtable])
        Write-Output $Hashtable
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

### S3 Cmdlets ###

<#
    .SYNOPSIS
    Retrieve SHA256 Hash for Payload
    .DESCRIPTION
    Retrieve SHA256 Hash for Payload
#>
function Global:Get-AwsHash {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            HelpMessage="String to hash")][String]$StringToHash
    )
 
    Process {
        $hasher = [System.Security.Cryptography.SHA256]::Create()

        $Hash = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($StringToHash))) -replace '-','').ToLower()

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
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="HTTP Request Method")][ValidateSet("OPTIONS","GET","HEAD","PUT","DELETE","TRACE","CONNECT")][String]$HTTPRequestMethod="GET",
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="URI")][String]$Uri="/",
        [parameter(
            Mandatory=$True,
            Position=6,
            HelpMessage="Content MD5")][Hashtable]$ContentMD5,
        [parameter(
            Mandatory=$True,
            Position=7,
            HelpMessage="Content Type")][Hashtable]$ContentType,
        [parameter(
            Mandatory=$True,
            Position=8,
            HelpMessage="Date")][DateTime]$DateTime,
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Headers")][Hashtable]$Headers=@{}
    )
 
    Process {
        # this Cmdlet follows the steps outlined in https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html

        # initialization
        if (!$DateTime) {
            $DateTime = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")        
        }

        Write-Debug "Constructing the CanonicalizedResource Element "

        $CanonicalizedResource = ""
        Write-Debug "1. Start with an empty string:`n$CanonicalizedResource"

        $CanonicalizedResource = $Uri
        Write-Debug "2. Add the bucketname for virtual host style:`n$EndpointUrl" 

        # only URL encode if service is not S3
        if ($Service -ne "s3" -and $Uri -ne "/") {
            $CanonicalURI = [System.Web.HttpUtility]::UrlEncode($Uri)
        }
        else {
            $CanonicalURI = $Uri
        }
        Write-Debug "3. Canonical URI:`n$CanonicalURI"

        Write-Debug "4. Canonical Query String:`n$CanonicalQueryString"

        $CanonicalRequest = "$HTTPRequestMethod`n$EndpointUrl`n$CanonicalURI`n$CanonicalQueryString`n"
        Write-Debug "5. Canonical Request:`n$CanonicalRequest"

        Write-Debug "Task 2: Calculate the Signature"

        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha.Key = [Text.Encoding]::UTF8.GetBytes($SecretAccessKey)

        $hasher = [System.Security.Cryptography.SHA256]::Create()

        $SortedHeaders = New-Object 'System.Collections.Generic.SortedDictionary[string, string]'
        $SortedHeaders["Host"] = $EndpointUrl

        foreach ($Key in $Headers.Keys) {
            $SortedHeaders[$Key]=$Headers[$Key]
        }

        $StringToSign = "$HTTPRequestMethod`n$ContentMD5`n$ContentType`n$Date`n$SignedHeaders`n$RequestPayloadHash"

        Write-Debug "StringToSign: $StringToSign"

        Write-Debug "CanonicalURI: $CanonicalURI"

        $CanonicalQueryString = ""
        if ($Query.Keys) {
            # using Sorted Dictionary as query need to be sorted by encoded keys
            $SortedEncodedQuery = New-Object 'System.Collections.Generic.SortedDictionary[string, string]'
            foreach ($Key in $Query.Keys) {
                # Key and value need to be URL encoded separately
                $SortedEncodedQuery[[System.Web.HttpUtility]::UrlEncode($Key)]=[System.Web.HttpUtility]::UrlEncode($Query[$Key])
            }
            foreach ($Key in $SortedEncodedQuery.Keys) {
                $CanonicalQueryString += "$Key=$($SortedEncodedQuery[$Key])&"
            }
            $CanonicalQueryString = $CanonicalQueryString -replace "&`$",""
        }
        else {
            $CanonicalQueryString = ""
        }
        Write-Debug "CanonicalQueryString: $CanonicalQueryString"

        Write-Debug "DateTime: $DateTime"
        Write-Debug "DateString: $DateString"

        $RequestPayloadHash = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($RequestPayload))) -replace '-','').ToLower()
        Write-Debug "RequestPayloadHash: $RequestPayloadHash"

        $CanonicalHeaders = "host:$EndpointUrl`nx-amz-content-sha256:$RequestPayloadHash`nx-amz-date:$DateTime`n"
        Write-Debug "CanonicalHeaders: $CanonicalHeaders"

        $SignedHeaders = "host;x-amz-content-sha256;x-amz-date"
        Write-Debug "SignedHeaders: $SignedHeaders"

        $CanonicalRequest = "$HTTPRequestMethod`n$CanonicalURI`n$CanonicalQueryString`n$CanonicalHeaders`n$SignedHeaders`n$RequestPayloadHash"
        Write-Debug "CanonicalRequest: $CanonicalRequest"

        $CanonicalRequestHash = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($CanonicalRequest))) -replace '-','').ToLower()
        Write-Debug "CanonicalRequestHash: $CanonicalRequestHash"

        $StringToSign = "AWS4-HMAC-SHA256`n$DateTime`n$DateString/$Region/$Service/aws4_request`n$CanonicalRequestHash"
        Write-Debug "StringToSign"

        $SignatureKey = GetSignatureKey $SecretAccessKey $DateString $Region $Service
        Write-Debug "SignatureKey: $SignatureKey"

        $Signature = ([BitConverter]::ToString((sign $SignatureKey $StringToSign)) -replace '-','').ToLower()
 
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
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
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

        if (!$Headers["host"]) { $Headers["host"] = $EndpointUrl }
        if (!$Headers["x-amz-date"]) { $Headers["x-amz-date"] = $DateTime }
        if (!$Headers["content-type"] -and $ContentType) { $Headers["content-type"] = $ContentType }
        $SortedHeaders = ConvertTo-SortedDictionary $Headers
        $CanonicalHeaders = (($SortedHeaders.GetEnumerator()  | % { "$($_.Key):$($_.Value)" }) -join "`n") + "`n"
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
    [CmdletBinding(DefaultParameterSetName="profile")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$True,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile="default",
        [parameter(
            ParameterSetName="credential",
            Mandatory=$False,
            Position=0,
            HelpMessage="Credential")][PSCredential]$Credential,
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
            Mandatory=$False,
            Position=2,
            HelpMessage="HTTP Request Method")][ValidateSet("OPTIONS","GET","HEAD","PUT","DELETE","TRACE","CONNECT")][String]$HTTPRequestMethod="GET",
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
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
            Position=6,
            HelpMessage="Force HTTP")][Switch]$HTTP,
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
            Position=9,
            HelpMessage="Region")][String]$Service="s3",
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SingerType="AWS4",
        [parameter(
            Mandatory=$False,
            Position=11,
            HelpMessage="Headers")][Hashtable]$Headers=@{},
        [parameter(
            Mandatory=$False,
            Position=12,
            HelpMessage="Content type")][String]$ContentType,
        [parameter(
            Mandatory=$False,
            Position=13,
            HelpMessage="Path where output should be saved to")][String]$FilePath,
        [parameter(
            Mandatory=$False,
            Position=14,
            HelpMessage="Bucket required for signing with V2 Authentication and virtual host style")][String]$Bucket,
        [parameter(
            Mandatory=$False,
            Position=15,
            HelpMessage="Use virtual host style for V2 Authentication")][Switch]$VirtualHostStyle
    )

    Begin {
        if ($Profile) {
            Write-Verbose "Using credentials from profile $Profile"
            if (!(Test-Path $AWS_CREDENTIALS_FILE)) {
                throw "Profile $Profile specified but no credentials defined!"
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
        if ($Credential) {
            Write-Verbose "Using credentials from credential object"
            $AccessKey = $Credential.UserName
            $SecretAccessKey = $Credential.GetNetworkCredential().Password
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
                $EndpointUrl = "s3.amazonaws.com"
            }
            else {
                $EndpointUrl = "s3.$Region.amazonaws.com"
            }
        }

        # remove port 80 and port 443 from EndpointUrl as they must not be included
        $EndpointUrl -replace ':80$','' -replace ':443$',''
    }
 
    Process {
        $DateTime = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
        $DateString = [DateTime]::UtcNow.ToString('yyyyMMdd')

        $CanonicalQueryString = ""
        if ($Query.Keys.Count -ge 1) {
            # using Sorted Dictionary as query need to be sorted by encoded keys
            $SortedEncodedQuery = New-Object 'System.Collections.Generic.SortedDictionary[string, string]'
            
            foreach ($Key in $Query.Keys) {
                # Key and value need to be URL encoded separately
                $SortedEncodedQuery[[System.Web.HttpUtility]::UrlEncode($Key)]=[System.Web.HttpUtility]::UrlEncode($Query[$Key])
            }
            foreach ($Key in $SortedEncodedQuery.Keys) {
                $CanonicalQueryString += "$Key=$($SortedEncodedQuery[$Key])&"
            }
            $CanonicalQueryString = $CanonicalQueryString -replace "&`$",""
        }

        $RequestPayloadHash=Get-AWSHash -StringToHash $RequestPayload
        
        if (!$Headers["host"]) { $Headers["host"] = $EndpointUrl }
        if (!$Headers["x-amz-content-sha256"]) { $Headers["x-amz-content-sha256"] = $RequestPayloadHash }
        if (!$Headers["x-amz-date"]) { $Headers["x-amz-date"] = $DateTime }
        if (!$Headers["content-type"] -and $ContentType) { $Headers["content-type"] = $ContentType }

        $SortedHeaders = ConvertTo-SortedDictionary $Headers

        $SignedHeaders = $SortedHeaders.Keys -join ";"

        if ($SingerType = "AWS4") {
            Write-Verbose "Using AWS Signature Version 4"
            $Signature = New-AwsSignatureV4 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl $EndpointUrl -Uri $Uri -CanonicalQueryString $CanonicalQueryString -HTTPRequestMethod $HTTPRequestMethod -RequestPayloadHash $RequestPayloadHash -DateTime $DateTime -DateString $DateString -Headers $Headers
            Write-Debug "Task 4: Add the Signing Information to the Request"
            # http://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
            $Headers["Authorization"]="AWS4-HMAC-SHA256 Credential=$AccessKey/$DateString/$Region/$Service/aws4_request,SignedHeaders=$SignedHeaders,Signature=$Signature"
            Write-Debug "Headers:`n$(ConvertTo-Json -InputObject $Headers)"
        }
        else {
            Write-Verbose "Using AWS Signature Version 2"
            $Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl $EndpointUrl -Uri $Uri -HTTPRequestMethod $HTTPRequestMethod -ContentMD5 $ContentMd5 -ContentType $ContentType -Date $DateTime -Bucket $Bucket -VirtualHostStyle:$VirtualHostStyle
        }

        if ($HTTP) {
            $Protocol = "http://"
        }
        else {
            $Protocol = "https://"
        }

        if ($CanonicalQueryString) {
            $Url = $Protocol + $EndpointUrl + $Uri + "?" + $CanonicalQueryString
        }
        else {
            $Url = $Protocol + $EndpointUrl + $Uri
        }

        try {
            #$Result = Invoke-RestMethod -Method $HTTPRequestMethod -Uri $Url -Headers $Headers -OutFile $FilePath
            $Result = Invoke-RestMethod -Method $HTTPRequestMethod -Uri $Url -Headers $Headers
        }
        catch {
            $ResponseBody = ParseExceptionBody $_.Exception.Response
            Write-Error "$HTTPRequestMethod to $Url failed with Exception $($_.Exception.Message) `n $responseBody"
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
            HelpMessage="Custom endpoint URL if different then AWS URL")][String]$EndpointUrl
    )
 
    Process {
        $Credentials = ConvertFrom-AwsConfigFile -AwsConfigFile $AWS_CREDENTIALS_FILE
        $Credentials[$Profile] = @{}
        $Credentials[$Profile]["aws_access_key_id"] = $AccessKey
        $Credentials[$Profile]["aws_secret_access_key"] = $SecretAccessKey
    }
}

<#
    .SYNOPSIS
    Get S3 Buckets
    .DESCRIPTION
    Get S3 Buckets
#>
function Global:Get-S3Buckets {
    [CmdletBinding(DefaultParameterSetName="profile")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile="default",
        [parameter(
            ParameterSetName="credential",
            Mandatory=$False,
            Position=0,
            HelpMessage="Credential")][PSCredential]$Credential,
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
            Mandatory=$False,
            Position=2,
            HelpMessage="EndpointUrl")][String]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="Skip SSL Certificate Check")][Switch]$SkipCertificateCheck
    )
 
    Process {
        $Uri = '/'
        $HTTPRequestMethod = "GET"
        if ($Profile) {
            $Result = Invoke-AwsRequest -Profile $Profile -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
        }
        elseif ($Credential) {
            $Result = Invoke-AwsRequest -Credential $Credential -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop
        }
        
        $Buckets = @()
        if ($Result.ListAllMyBucketsResult) {
            foreach ($Bucket in $Result.ListAllMyBucketsResult.Buckets.ChildNodes) {
                $Buckets += [PSCustomObject]@{Name=$Bucket.Name;CreationDate=$Bucket.CreationDate}
            }
            $Owner = [PSCustomObject]@{ID=$Result.ListAllMyBucketsResult.Owner.ID;DisplayName=$Result.ListAllMyBucketsResult.Owner.DisplayName}
        }
        $Buckets | Add-Member -MemberType NoteProperty -Name OwnerId -Value $Owner.ID
        $Buckets | Add-Member -MemberType NoteProperty -Name OwnerDisplayName -Value $Owner.DisplayName
        Write-Output $Buckets
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket
    .DESCRIPTION
    Get S3 Bucket
#>
function Global:Get-S3Bucket {
    [CmdletBinding(DefaultParameterSetName="profile")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile="default",
        [parameter(
            ParameterSetName="credential",
            Mandatory=$False,
            Position=0,
            HelpMessage="Credential")][PSCredential]$Credential,
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
            $EndpointUrl = $Bucket + "." + $EndpointUrl
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
        elseif ($Credential) {
            $Result = Invoke-AwsRequest -Credential $Credential -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }

        $Objects = $Result.ListBucketResult.Contents | ? { $_ }
        $Objects | Add-Member -MemberType NoteProperty -Name Bucket -Value $Result.ListBucketResult.Name

        if ($Result.ListBucketResult.IsTruncated -eq "true" -and $MaxKeys -eq 0) {
            Write-Verbose "1000 Objects were returned and max keys was not limited so continuing to get all objects"
            Write-Debug "NextMarker: $($Result.ListBucketResult.NextMarker)"
            if ($Profile) {
                $Objects += Get-S3Bucket -Profile $Profile -EndpointUrl $EndpointUrl -SkipCertificateCheck:$SkipCertificateCheck -UrlStyle $UrlStyle -Bucket $Bucket -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $Result.ListBucketResult.NextContinuationToken -Marker $Result.ListBucketResult.NextMarker
            }
            elseif ($Credential) {
                $Objects += Get-S3Bucket -Credential $Credential -EndpointUrl $EndpointUrl -SkipCertificateCheck:$SkipCertificateCheck -UrlStyle $UrlStyle -Bucket $Bucket -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $Result.ListBucketResult.NextContinuationToken -Marker $Result.ListBucketResult.NextMarker
            }
            else {
                $Objects += Get-S3Bucket -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl $EndpointUrl -SkipCertificateCheck:$SkipCertificateCheck -UrlStyle $UrlStyle -Bucket $Bucket -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $Result.ListBucketResult.NextContinuationToken -Marker $Result.ListBucketResult.NextMarker
            }            
        }

        Write-Output $Objects
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket Consistency Setting
    .DESCRIPTION
    Get S3 Bucket Consistency Setting
#>
function Global:Get-S3BucketConsistency {
    [CmdletBinding(DefaultParameterSetName="profile")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile="default",
        [parameter(
            ParameterSetName="credential",
            Mandatory=$False,
            Position=0,
            HelpMessage="Credential")][PSCredential]$Credential,
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
            $EndpointUrl = $Bucket + "." + $EndpointUrl
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
        elseif ($Credential) {
            $Result = Invoke-AwsRequest -Credential $Credential -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
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
    [CmdletBinding(DefaultParameterSetName="profile")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile="default",
        [parameter(
            ParameterSetName="credential",
            Mandatory=$False,
            Position=0,
            HelpMessage="Credential")][PSCredential]$Credential,
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
            $EndpointUrl = $Bucket + "." + $EndpointUrl
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
        elseif ($Credential) {
            $Result = Invoke-AwsRequest -Credential $Credential -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
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
    [CmdletBinding(DefaultParameterSetName="profile")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile="default",
        [parameter(
            ParameterSetName="credential",
            Mandatory=$False,
            Position=0,
            HelpMessage="Credential")][PSCredential]$Credential,
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
        elseif ($Credential) {
            $Result = Invoke-AwsRequest -Credential $Credential -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
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
    [CmdletBinding(DefaultParameterSetName="profile")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile="default",
        [parameter(
            ParameterSetName="credential",
            Mandatory=$False,
            Position=0,
            HelpMessage="Credential")][PSCredential]$Credential,
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
            $EndpointUrl = $Bucket + "." + $EndpointUrl
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
        elseif ($Credential) {
            $Result = Invoke-AwsRequest -Credential $Credential -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
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
    [CmdletBinding(DefaultParameterSetName="profile")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile="default",
        [parameter(
            ParameterSetName="credential",
            Mandatory=$False,
            Position=0,
            HelpMessage="Credential")][PSCredential]$Credential,
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
            $EndpointUrl = $Bucket + "." + $EndpointUrl
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
        elseif ($Credential) {
            $Result = Invoke-AwsRequest -Credential $Credential -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
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
    [CmdletBinding(DefaultParameterSetName="profile")]

    PARAM (
        [parameter(
            ParameterSetName="profile",
            Mandatory=$False,
            Position=0,
            HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][String]$Profile="default",
        [parameter(
            ParameterSetName="credential",
            Mandatory=$False,
            Position=0,
            HelpMessage="Credential")][PSCredential]$Credential,
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
            $EndpointUrl = $Bucket + "." + $EndpointUrl
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
        elseif ($Credential) {
            $Result = Invoke-AwsRequest -Credential $Credential -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
        else {
            $Result = Invoke-AwsRequest -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -HTTPRequestMethod $HTTPRequestMethod -EndpointUrl $EndpointUrl -Uri $Uri -SkipCertificateCheck:$SkipCertificateCheck -Query $Query -ErrorAction Stop
        }
    }
}
function New-GithubRelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$Version,
        [Parameter(Mandatory = $true)][String]$Name,
        [Parameter(Mandatory = $true)][String]$ReleaseNotes,
        [Parameter(Mandatory = $true)][String]$OutputDirectory,
        [Parameter(Mandatory = $true)][String]$FileName,
        [Parameter(Mandatory = $false)][String]$GitHubUsername="ffeldhaus",
        [Parameter(Mandatory = $false)][String]$GitHubRepository="StorageGRID-Webscale",
        [Parameter(Mandatory = $false)][switch]$Draft=$false,
        [Parameter(Mandatory = $false)][switch]$PreRelease=$false

    )

    # The github API key must be available in $GitHubApiKey (https://github.com/blog/1509-personal-api-tokens)

    # The Commit SHA for corresponding to this release
    $CommitId = git rev-list -n 1 "refs/tags/$Version"

    $ReleaseData = @{
       tag_name = $Version;
       target_commitish = $CommitId;
       name = $Name;
       body = $ReleaseNotes;
       draft = $Draft.IsPresent;
       prerelease = $PreRelease.IsPresent;
     }

    $ReleaseParams = @{
       Uri = "https://api.github.com/repos/$GitHubUsername/$GitHubRepository/releases";
       Method = 'POST';
       Headers = @{
         Authorization = 'token ' + $GitHubApiKey;
       }
       ContentType = 'application/json';
       Body = (ConvertTo-Json $releaseData -Compress)
     }

     $Result = Invoke-RestMethod @ReleaseParams 
     $UploadUri = $Result | Select -ExpandProperty upload_url
     $UploadUri = $UploadUri -replace '\{\?name,label\}',"?name=$FileName"
     $UploadFile = Join-Path -path $OutputDirectory -childpath $FileName

     $uploadParams = @{
       Uri = $UploadUri;
       Method = 'POST';
       Headers = @{
         Authorization = 'token ' + $GitHubApiKey;
       }
       ContentType = 'application/zip';
       InFile = $UploadFile
     }

    $Result = Invoke-RestMethod @UploadParams
}


<#
.SYNOPSIS
Generates a manifest for the module and bundles all of the module source files and manifest into a distributable ZIP file.
.DESCRIPTION 
Generates a manifest for the module and bundles all of the module source files and manifest into a distributable ZIP file.
.EXAMPLE
New-SGWRelease.
#>
function New-SGWRelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][String]$Author='Florian Feldhaus',
        [Parameter(Mandatory = $false)][String]$Company='NetApp Deutschland GmbH',
        [Parameter(Mandatory = $true)][String]$Name,
        [Parameter(Mandatory = $true)][String]$ReleaseNotes,
        [Parameter(Mandatory = $false)][switch]$Major,
        [Parameter(Mandatory = $false)][switch]$Minor,
        [Parameter(Mandatory = $false)][switch]$Build,
        [Parameter(Mandatory = $false)][switch]$Release
    )

    $ErrorActionPreference = "Stop"

    $CurrentVersion = git tag | ? { $_ -notmatch "\*" } | Select -last 1

    if (!$CurrentVersion) { $CurrentVersion = "0.1.0" }

    $ModuleVersion = New-Object System.Version($CurrentVersion)
    if ($Major) { $ModuleVersion = New-Object System.Version(($ModuleVersion.Major+1),0,0) }
    if ($Minor) { $ModuleVersion = New-Object System.Version($ModuleVersion.Major,($ModuleVersion.Minor+1),0) }
    if ($Build) { $ModuleVersion = New-Object System.Version($ModuleVersion.Major,$ModuleVersion.Minor,($ModuleVersion.Build+1)) }

    Write-Host "Running Pester tests"
    # Invoke-SGWTests

    Write-Host "Building release for version $ModuleVersion"

    $scriptPath = Split-Path -LiteralPath $(if ($PSVersionTable.PSVersion.Major -ge 3) { $PSCommandPath } else { & { $MyInvocation.ScriptName } })

    $src = (Join-Path (Split-Path $PSScriptRoot) 'src')
    $dst = (Join-Path (Split-Path $PSScriptRoot) 'release')
    $out = (Join-Path (Split-Path $PSScriptRoot) 'out')

    if (Test-Path $dst) {
        Remove-Item $dst -Force -Recurse
    }
    New-Item $dst -ItemType Directory -Force | Out-Null

    Write-Host "Creating module manifest..."

    $manifestFileName = Join-Path $dst 'StorageGRID-Webscale.psd1'

    $functionsToExport = Get-Command -Module StorageGRID-Webscale -Name *-SGW* | Select -ExpandProperty Name

    $tags = @("StorageGRID-Webscale","SGW","NetApp")

    New-ModuleManifest `
        -Path $manifestFileName `
        -ModuleVersion $ModuleVersion `
        -Guid 3f827027-aba0-4ed9-af5d-05c88f0470cd `
        -Author $Author `
        -CompanyName $Company `
        -Copyright "(c) $((Get-Date).Year) NetApp Deutschland GmbH. All rights reserved." `
        -Description 'StorageGRID-Webscale Powershell Cmdlet.' `
        -PowerShellVersion '3.0' `
        -DotNetFrameworkVersion '4.5' `
        -NestedModules (Get-ChildItem $src\*.psm1,$src\*.dll | % { $_.Name }) `
        -FormatsToProcess (Get-ChildItem $src\*.format.ps1xml | % { $_.Name }) `
        -LicenseUri "https://github.com/ffeldhaus/StorageGRID-Webscale/blob/master/LICENSE" `
        -ProjectUri "https://github.com/ffeldhaus/StorageGRID-Webscale" `
        -RootModule "StorageGRID-Webscale" `
        -FunctionsToExport $functionsToExport `
        -Tags $tags

    Write-Host "Copying file to release folder..."

    # Copy the Module files to the dist folder.
    Copy-Item -Path "$src\*.psm1" `
              -Destination $dst `
              -Recurse

    Write-Host "Copying files to release folder"

    Copy-Item -Path "$scriptPath\..\README.md" `
              -Destination "$dst\README.txt"

    Copy-Item -Path "$scriptPath\..\LICENSE" `
              -Destination "$dst\LICENSE"

    Write-Host "Signing PowerShell files..."

    # Code Signing
    $cert = Get-ChildItem cert:\CurrentUser\My -CodeSigningCert
    Get-ChildItem $dst\*.ps*  | % { $_.FullName } | Set-AuthenticodeSignature -Certificate $cert | Out-Null
    
    Write-Host "Creating the release archive..."

    # Requires .NET 4.5
    [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null

    $zipFileName = Join-Path $out "StorageGRID-Webscale.zip"

    # Overwrite the ZIP if it already already exists.
    if (Test-Path $zipFileName) {
        Remove-Item $zipFileName -Force
    }

    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    $includeBaseDirectory = $false
    [System.IO.Compression.ZipFile]::CreateFromDirectory($dst, $zipFileName, $compressionLevel, $includeBaseDirectory)

    Write-Host "Release zip file $zipFileName successfully created!" -ForegroundColor Green

    Write-Host "Creating MSI installers..."
    Start-WixBuild -Path $dst -OutputFolder $out -ProductShortName "StorageGRID-Webscale" -ProductName "StorageGRID-Webscale PowerShell Cmdlets" -ProductVersion $ModuleVersion -Manufacturer $Author -IconFile $PSScriptRoot\icon.ico -BannerFile $PSScriptRoot\banner.bmp -DialogFile $PSScriptRoot\dialog.bmp -UpgradeCodeX86 "CCEE2853-0FC5-4D1B-8485-4625D9D75CF8" -UpgradeCodeX64 "7A7CD8B3-CD26-4829-8E05-08D7D9CFA5CA"

    Write-Host "Release MSI Installer OnCommand_Insight_$($ModuleVersion)_x64.msi and OnCommand_Insight_$($ModuleVersion)_x86.msi successfully created!" -ForegroundColor Green

    Remove-Item $dst\.wix.json

    if ($Release) { 
        Write-Host "Publishing Module to PowerShell Gallery"
        Publish-Module -Name "StorageGRID-Webscale" -NuGetApiKey $NuGetApiKey

        Write-Host "Creating git tag"
        & git pull
        & git tag $ModuleVersion
        if ($Major) { 
            Write-Host "Creating new git branch"
            & git branch $ModuleVersion
            Write-Host "New Git Branch $ModuleVersion created"
        }
        try {
            & git push 2> $null
            & git push --all 2> $null
            & git push --tags 2> $null
        }
        catch {
        }
        
        Write-Host "Creating GitHub release"
        New-GithubRelease -Version $ModuleVersion -Name $Name -ReleaseNotes $ReleaseNotes -FileName "StorageGRID-Webscale.zip" -OutputDirectory $out
    }
}

function Invoke-SGWTests {
    $SGWServer = 'localhost'
    $SGWCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "root",("netapp01" | ConvertTo-SecureString -AsPlainText -Force)

    $VerbosePreference = "Continue"

    $Result = Invoke-Pester -Script @{Path='./';Parameters=@{Server=$SGWServer;Credential=$SGWCredential;Version=$Version;Record=$Record}} -PassThru

    if ($Result.FailedCount -gt 0) {
        Write-Error "Aborting due to test errors"
    }
}
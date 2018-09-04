Import-Module "$PSScriptRoot\StorageGRID-Webscale"

if (!$Name) {
    Throw "Variable SgwServerName not set!"
}

if (!$Credential) {
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "root",("netapp01" | ConvertTo-SecureString -AsPlainText -Force)
}

Write-Host "Running tests against StorageGRID $Name"

## accounts ##

Describe "StorageGRID Tests" {
    Context "Connect with StorageGRID Server" {
        it "succeeds with mandatory parameters" {
            $Server = Connect-SgwServer -Name $Name
        }
    }

    Context "retrieving accounts" {
        it "succeeds with no parameters" {
            Connect-SgwServer -Name $Name -Credential $Credential -Insecure

            $Accounts = Get-SgwAccounts
            $Accounts  | Should Not BeNullOrEmpty

            Disconnect-SgwServer

            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnits | ValidateAcquisitionUnit
        }

        it "succeeds with getting datasources" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits -datasources
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnits | ValidateAcquisitionUnit
            $AcquisitionUnits.datasources | ValidateDatasource
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $Global:CurrentOciServer | Should BeNullOrEmpty

            $AcquisitionUnits = Get-OciAcquisitionUnits -Server $OciServer
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnits | ValidateAcquisitionUnit
        }
    }
}
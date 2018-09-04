#Write-Information "Setup RedHat VM via PowerShell for Docker deployment"

#Install-Module -Name VMware.PowerCLI –Scope CurrentUser

#Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false

#Import-Module VMware.PowerCLI

# Install RHEL 7 VM with at least 32 Cores and 32GB Memory and one OS disk and one docker disk with 2TB or more
# - create LVM paritions for StorageGRID
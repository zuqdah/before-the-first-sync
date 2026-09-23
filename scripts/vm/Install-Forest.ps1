#requires -Version 5.1
<#
    .SYNOPSIS
        Promotes this machine to the root domain controller of a new forest.
    .DESCRIPTION
        Runs on the virtual machine through Run Command. Promotion reboots the
        machine, which Run Command cannot span, so the caller waits for the
        agent to come back and then runs the next script. That is why this does
        one thing and reports what it did before the connection drops.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$ErrorActionPreference = 'Stop'

function Get-RandomSecret {
    <#
        .SYNOPSIS
            Builds a random SecureString without the plaintext ever existing.
        .DESCRIPTION
            The characters are appended one at a time, so there is no managed
            string holding the secret for the garbage collector to leave lying
            in memory. ConvertTo-SecureString -AsPlainText would be shorter and
            would create exactly that string, which is what PSScriptAnalyzer
            objects to and it is right to.

            The four fixed characters at the end satisfy the domain complexity
            policy deterministically, rather than generating and retrying until
            a random value happens to qualify.
    #>
    [OutputType([System.Security.SecureString])]
    param([int]$Length = 28)

    $alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $secret = [System.Security.SecureString]::new()
    $bytes = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    foreach ($byte in $bytes) {
        $secret.AppendChar($alphabet[$byte % $alphabet.Length])
    }
    foreach ($char in 'a', 'A', '1', '!') { $secret.AppendChar($char) }
    $secret.MakeReadOnly()
    return $secret
}

if ((Get-WindowsFeature -Name AD-Domain-Services).Installed) {
    Write-Output 'AD-Domain-Services already installed.'
}
else {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
    Write-Output 'AD-Domain-Services installed.'
}

# Already a domain controller: the caller retried, or the reboot happened
# faster than it expected. Promoting again would fail, so say so and stop.
$role = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
if ($role -ge 4) {
    Write-Output "ALREADY_PROMOTED role=$role"
    exit 0
}

Import-Module ADDSDeployment

# The directory services restore mode password is generated here and never
# leaves the machine. It has to exist, but nothing outside this script needs
# it: the domain controller is destroyed at the end of the run, and a secret
# that is never transmitted cannot be intercepted, logged by Run Command, or
# left in a state file. Generating it on the far side is strictly better than
# passing one in, even protected.
$safe = Get-RandomSecret

Write-Output "PROMOTING $DomainName"
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName (($DomainName -split '\.')[0].ToUpperInvariant()) `
    -InstallDns `
    -SafeModeAdministratorPassword $safe `
    -NoRebootOnCompletion:$false `
    -Force `
    -Confirm:$false

#requires -Version 5.1
<#
    .SYNOPSIS
        Builds the organizational units and users the assessment is run against.
    .DESCRIPTION
        Runs on the domain controller through Run Command. The object set is
        passed in as compressed JSON rather than read from disk, because Run
        Command delivers a script and its parameters and nothing else -- there
        is no repository on the machine.

        Defects are created deliberately and exactly as declared. Anything this
        script silently corrected would be a defect the assessment then cannot
        find, which would make the proof vacuous.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ObjectSetBase64
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

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

function Expand-Payload {
    param([Parameter(Mandatory)][string]$Base64)
    $bytes = [Convert]::FromBase64String($Base64)
    # Not $input: that is an automatic variable holding the pipeline, and
    # assigning to it breaks anything downstream that reads it.
    $stream = New-Object System.IO.MemoryStream(, $bytes)
    $gzip = New-Object System.IO.Compression.GZipStream($stream, [System.IO.Compression.CompressionMode]::Decompress)
    $reader = New-Object System.IO.StreamReader($gzip)
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}

$plan = Expand-Payload -Base64 $ObjectSetBase64 | ConvertFrom-Json
$root = (Get-ADDomain).DistinguishedName
# Generated here and never returned. These accounts exist to be read by an
# assessment, not signed into, so the password is an implementation detail of
# New-ADUser rather than a credential anybody needs -- and one that is never
# transmitted cannot leak.
$secure = Get-RandomSecret

# Parents first, so a nested unit finds the container it belongs in.
$ouPath = @{}
foreach ($ou in ($plan.organizationalUnits | Sort-Object { if ($_.PSObject.Properties['parent'] -and $_.parent) { 1 } else { 0 } })) {
    $parentDn = if ($ou.PSObject.Properties['parent'] -and $ou.parent) { $ouPath[$ou.parent] } else { $root }
    $dn = "OU=$($ou.name),$parentDn"
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.name)'" -SearchBase $parentDn -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou.name -Path $parentDn -ProtectedFromAccidentalDeletion:$false | Out-Null
    }
    $ouPath[$ou.name] = $dn
    Write-Output "OU $dn"
}

$created = 0
foreach ($user in $plan.users) {
    $path = $ouPath[$user.ou]
    if (-not $path) { throw "User $($user.sam) names OU '$($user.ou)', which the plan does not define." }

    if (Get-ADUser -Filter "SamAccountName -eq '$($user.sam)'" -ErrorAction SilentlyContinue) {
        Write-Output "EXISTS $($user.sam)"
        continue
    }

    $arguments = @{
        Name                  = $user.sam
        SamAccountName        = $user.sam
        Path                  = $path
        AccountPassword       = $secure
        Enabled               = $true
        ChangePasswordAtLogon = $false
    }

    # New-ADUser refuses a malformed userPrincipalName, and two of the planted
    # defects are malformed on purpose. They are set afterwards with
    # Set-ADObject, which writes the attribute without validating it -- which
    # is also how they get into a real forest.
    $deferredUpn = $null
    if ($user.PSObject.Properties['upn'] -and $user.upn) {
        if ($user.upn -match '\s') { $deferredUpn = $user.upn }
        else { $arguments['UserPrincipalName'] = $user.upn }
    }

    New-ADUser @arguments
    $created++

    $target = "CN=$($user.sam),$path"
    if ($deferredUpn) {
        Set-ADObject -Identity $target -Replace @{ userPrincipalName = $deferredUpn }
    }

    if ($user.PSObject.Properties['proxyAddresses'] -and $user.proxyAddresses) {
        Set-ADObject -Identity $target -Replace @{ proxyAddresses = [string[]]$user.proxyAddresses }
    }

    if ($user.PSObject.Properties['enabled'] -and $user.enabled -eq $false) {
        Disable-ADAccount -Identity $target
    }

    Write-Output "USER $($user.sam) defect=$(if ($user.defect) { $user.defect } else { 'none' })"
}

Write-Output "CREATED $created"

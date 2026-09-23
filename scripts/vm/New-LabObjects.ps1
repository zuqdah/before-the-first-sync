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

    # Every userPrincipalName is written after creation, never passed to
    # New-ADUser. Two reasons, and the second cost a live run:
    #
    # New-ADUser validates the format, so a deliberately malformed value is
    # refused outright.
    #
    # Active Directory also enforces UPN uniqueness at creation, so the second
    # half of a duplicate pair is refused -- and with ErrorActionPreference
    # Stop that aborted the whole script, leaving eight of twelve objects
    # uncreated and the assessment reporting their defects as "not found".
    #
    # Set-ADObject writes the attribute without either check, which is also how
    # duplicates and malformed names get into real forests: not through the
    # account creation tooling, but through something writing attributes
    # directly afterwards.
    New-ADUser @arguments
    $created++

    $target = "CN=$($user.sam),$path"
    if ($user.PSObject.Properties['upn'] -and $user.upn) {
        Set-ADObject -Identity $target -Replace @{ userPrincipalName = $user.upn }
    }

    # mail and proxyAddresses carry no uniqueness constraint in Active
    # Directory, which is why the duplicates planted in this forest are on
    # these attributes rather than on userPrincipalName.
    if ($user.PSObject.Properties['mail'] -and $user.mail) {
        Set-ADObject -Identity $target -Replace @{ mail = [string]$user.mail }
    }

    if ($user.PSObject.Properties['proxyAddresses'] -and $user.proxyAddresses) {
        Set-ADObject -Identity $target -Replace @{ proxyAddresses = [string[]]$user.proxyAddresses }
    }

    if ($user.PSObject.Properties['enabled'] -and $user.enabled -eq $false) {
        Disable-ADAccount -Identity $target
    }

    Write-Output "USER $($user.sam) defect=$(if ($user.defect) { $user.defect } else { 'none' })"
}

# The count is asserted here rather than left for the assessment to notice.
# When this script aborted part way through, the symptom three steps later was
# an assessment reporting declared defects as "not found" -- which reads like a
# broken check rather than a directory that was never fully built. A step that
# half-succeeded has to say so at the point it happens.
$expected = @($plan.users).Count
$present = @(Get-ADUser -Filter * -SearchBase $root -SearchScope Subtree |
    Where-Object { $_.DistinguishedName -match ',OU=' }).Count

Write-Output "CREATED $created EXPECTED $expected PRESENT $present"
if ($present -lt $expected) {
    throw "The plan declares $expected users and the forest holds $present in its organizational units. The assessment would report the missing ones as defects it failed to find."
}

# Run Command reports the invocation, not the script. An exception in here
# still comes back as a successful call with the error buried in the response
# body, so a caller that only reads the exit code sees success over a script
# that threw -- which is how a half-built directory reached the assessment and
# looked like a broken check. The caller asserts this line is present.
Write-Output 'SCRIPT_OK'

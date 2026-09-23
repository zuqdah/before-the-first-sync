#requires -Version 5.1
<#
    .SYNOPSIS
        Reads the forest and returns the attributes an assessment needs.
    .DESCRIPTION
        Runs on the domain controller through Run Command, which caps its
        response at about 4 KB and truncates from the FRONT -- so an oversized
        payload loses its opening brace and stops being parseable at all,
        rather than arriving visibly short. A previous lab in this series lost
        an afternoon to exactly that.

        So the facts are compressed and base64-encoded before being printed,
        and the size is checked against the cap before anything is returned.
        Only measurements travel: no descriptions, no timestamps, nothing the
        assessment does not read.
#>
[CmdletBinding()]
param(
    [int]$MaxBytes = 3500
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$attributes = @(
    'sAMAccountName', 'userPrincipalName', 'distinguishedName', 'mail',
    'proxyAddresses', 'displayName', 'givenName', 'surname', 'enabled'
)

# Only objects in organizational units. The built-in CN=Users container holds
# krbtgt, Guest and the machine's own administrator, none of which are ever in
# sync scope -- and the first live run duly reported all three as Blocking for
# having no userPrincipalName, which is true and completely useless. An
# assessment that reports on objects that will never sync is generating exactly
# the noise this lab exists to avoid, so the export is scoped the way a real
# one would be: to what is actually going to be synchronised.
$users = Get-ADUser -Filter * -Properties $attributes |
    Where-Object { $_.DistinguishedName -match ',OU=' } | ForEach-Object {
    $record = [ordered]@{
        sAMAccountName    = $_.sAMAccountName
        distinguishedName = $_.distinguishedName
        enabled           = [bool]$_.Enabled
    }
    # Absent attributes are omitted rather than sent as empty strings. The
    # assessment distinguishes "no userPrincipalName" from "an empty one", and
    # flattening them here would hide a finding.
    foreach ($name in 'userPrincipalName', 'mail', 'displayName', 'givenName', 'surname') {
        $value = $_.$name
        if ($value) { $record[$name] = [string]$value }
    }
    $addresses = @($_.proxyAddresses | Where-Object { $_ })
    if ($addresses.Count) { $record['proxyAddresses'] = $addresses }
    [pscustomobject]$record
}

$payload = [pscustomobject]@{
    domain = (Get-ADDomain).DNSRoot
    users  = @($users)
} | ConvertTo-Json -Depth 5 -Compress

$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
$output = New-Object System.IO.MemoryStream
$gzip = New-Object System.IO.Compression.GZipStream($output, [System.IO.Compression.CompressionMode]::Compress, $true)
$gzip.Write($bytes, 0, $bytes.Length)
$gzip.Dispose()
$encoded = [Convert]::ToBase64String($output.ToArray())

if ($encoded.Length -gt $MaxBytes) {
    throw "The encoded facts are $($encoded.Length) bytes and Run Command will truncate them from the front, leaving unparseable output. Narrow the query or hand the facts over through storage instead."
}

Write-Output "FACTS_BEGIN"
Write-Output $encoded
Write-Output "FACTS_END"
Write-Output "users=$(@($users).Count) encoded=$($encoded.Length)B raw=$($bytes.Length)B"

# Run Command reports the invocation, not the script. An exception in here
# still comes back as a successful call with the error buried in the response
# body, so a caller that only reads the exit code sees success over a script
# that threw -- which is how a half-built directory reached the assessment and
# looked like a broken check. The caller asserts this line is present.
Write-Output 'SCRIPT_OK'

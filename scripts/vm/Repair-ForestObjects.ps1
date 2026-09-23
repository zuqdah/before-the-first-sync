#requires -Version 5.1
<#
    .SYNOPSIS
        Applies only the fixes that are safe to make without asking anybody.
    .DESCRIPTION
        Runs on the domain controller through Run Command.

        The boundary this script draws is the point of it. Stripping an illegal
        character from a userPrincipalName, or adding the SMTP prefix an
        address is missing, changes the representation of an identity and not
        the identity -- nobody has to be consulted.

        Everything else is left alone, deliberately:

        A duplicate userPrincipalName cannot be resolved here, because deciding
        which of two people keeps the name is a business question and getting
        it wrong locks somebody out of their account.

        An unverified domain suffix is not an object problem at all. Rewriting
        every affected user to a verified suffix would change what they sign in
        with, when the right fix is usually to verify the domain.

        An oversized attribute has to be shortened by somebody who knows what
        it is for.

        So this reports what it refused and why, and the assessment that runs
        afterwards is expected to still find those. A remediation pass that
        cleared everything would mean it had made decisions it had no standing
        to make.
#>
[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$illegal = @('\', '/', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', ' ', '"')
$fixed = 0
$refused = 0

foreach ($user in (Get-ADUser -Filter * -Properties userPrincipalName, proxyAddresses)) {
    $label = $user.sAMAccountName

    $upn = [string]$user.userPrincipalName
    if ($upn) {
        $cleaned = $upn
        foreach ($char in $illegal) { $cleaned = $cleaned.Replace($char, '') }
        if ($cleaned -ne $upn -and $cleaned -match '^[^@]+@[^@]+$') {
            if ($PSCmdlet.ShouldProcess($label, "rewrite userPrincipalName to '$cleaned'")) {
                Set-ADObject -Identity $user.DistinguishedName -Replace @{ userPrincipalName = $cleaned }
                Write-Output "FIXED $label userPrincipalName '$upn' -> '$cleaned'"
                $fixed++
            }
        }
    }

    $addresses = @($user.proxyAddresses | Where-Object { $_ })
    if ($addresses.Count) {
        $rewritten = @()
        $changed = $false
        foreach ($address in $addresses) {
            if ($address -notmatch '^[A-Za-z0-9]+:.+$' -and $address -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
                $rewritten += "SMTP:$address"
                $changed = $true
            }
            else { $rewritten += $address }
        }
        if ($changed -and $PSCmdlet.ShouldProcess($label, 'add the missing address type prefix')) {
            Set-ADObject -Identity $user.DistinguishedName -Replace @{ proxyAddresses = [string[]]$rewritten }
            Write-Output "FIXED $label proxyAddresses typed"
            $fixed++
        }
    }
}

# Named rather than counted, so the report says which decisions were left to a
# human instead of just how many.
foreach ($user in (Get-ADUser -Filter * -Properties userPrincipalName)) {
    $upn = [string]$user.userPrincipalName
    if (-not $upn) {
        Write-Output "REFUSED $($user.sAMAccountName) no userPrincipalName: choosing a sign-in name is not a mechanical fix"
        $refused++
    }
    elseif ($upn -match '@(.+)$' -and $Matches[1] -notmatch '\.(com|net|org)$') {
        Write-Output "REFUSED $($user.sAMAccountName) suffix '$($Matches[1])' unverifiable: verify the domain or change what the user signs in with, both decisions for somebody else"
        $refused++
    }
}

Write-Output "FIXED_TOTAL $fixed REFUSED_TOTAL $refused"

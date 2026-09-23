#requires -Version 7.0

Set-StrictMode -Version Latest

# Entra rejects these outright in a userPrincipalName. The list is short and
# specific on purpose: a validator that refuses anything unusual sends people
# renaming accounts that would have synced perfectly well.
$script:IllegalUpnCharacters = @('\', '/', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', ' ', '"')

# Attribute ceilings Entra enforces. Anything longer is truncated or refused,
# and which of those two happens is not something to find out during a cutover.
$script:AttributeLimits = @{
    userPrincipalName = 113
    displayName       = 256
    givenName         = 64
    surname           = 64
    sAMAccountName    = 20
    mailNickname      = 64
}

function Get-OptionalProperty {
    <#
        .SYNOPSIS
            Reads a property that may be absent, without tripping StrictMode.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-AddressKey {
    <#
        .SYNOPSIS
            Normalises a proxyAddresses entry so duplicates compare equal.
        .DESCRIPTION
            proxyAddresses carries its type as a prefix, and the case of that
            prefix is meaningful: SMTP: marks the primary address, smtp: a
            secondary one. The address itself is not case sensitive. Comparing
            raw strings therefore misses the most common duplicate of all --
            one object holding an address as primary while another holds the
            same address as an alias, which Entra refuses and which no amount
            of reading the two values side by side makes obvious.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Address)

    $value = $Address.Trim()
    $separator = $value.IndexOf(':')
    if ($separator -lt 0) { return "smtp:$($value.ToLowerInvariant())" }

    $type = $value.Substring(0, $separator).ToLowerInvariant()
    $rest = $value.Substring($separator + 1).ToLowerInvariant()
    return "${type}:${rest}"
}

function Test-ObjectReadiness {
    <#
        .SYNOPSIS
            Checks whether one directory object will survive its first sync.
        .DESCRIPTION
            Everything here is per-object. Uniqueness needs the whole set and
            lives in Find-DuplicateAttribute.

            The rule the rest of this function exists to serve: an attribute
            that cannot be evaluated is never reported as passing. If the
            userPrincipalName is missing there is no suffix to check, and a
            readiness report that quietly counts that object as having a valid
            suffix is worse than one that never looked -- it has told somebody
            the object is ready.
        .PARAMETER Object
            A directory object with the attributes Entra reads.
        .PARAMETER VerifiedDomain
            Domain suffixes verified in the target tenant.
        .OUTPUTS
            One finding per problem. No findings means ready.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$VerifiedDomain
    )

    $dn = [string](Get-OptionalProperty $Object 'distinguishedName')
    $sam = [string](Get-OptionalProperty $Object 'sAMAccountName')
    $label = if ($sam) { $sam } elseif ($dn) { $dn } else { '(unidentified object)' }

    $upn = [string](Get-OptionalProperty $Object 'userPrincipalName')

    # The UPN is load-bearing: it becomes the sign-in name. Its absence is not
    # one finding among several, it is the reason several other checks cannot
    # run, so it is reported that way.
    if ([string]::IsNullOrWhiteSpace($upn)) {
        [pscustomobject]@{
            Severity = 'Blocking'; Object = $label; Attribute = 'userPrincipalName'
            Detail = "$label has no userPrincipalName. It will sync with one derived from the tenant's default domain, which is not the name anybody expects to sign in with, and the suffix and character checks cannot be run at all."
            Remediation = 'Set userPrincipalName to a verified domain suffix before the first sync.'
            AutoRemediable = $false
        }
    }
    else {
        $at = $upn.LastIndexOf('@')
        if ($at -lt 1 -or $at -eq $upn.Length - 1) {
            [pscustomobject]@{
                Severity = 'Blocking'; Object = $label; Attribute = 'userPrincipalName'
                Detail = "'$upn' is not a valid userPrincipalName: it needs a local part and a domain suffix separated by @."
                Remediation = 'Correct the userPrincipalName to the form user@domain.'
                AutoRemediable = $false
            }
        }
        else {
            $suffix = $upn.Substring($at + 1)
            if ($VerifiedDomain.Count -eq 0) {
                # No domain list means the check could not be made. Saying so
                # beats assuming either answer.
                [pscustomobject]@{
                    Severity = 'Unevaluated'; Object = $label; Attribute = 'userPrincipalName'
                    Detail = "The suffix '$suffix' could not be checked because no verified domains were supplied."
                    Remediation = 'Supply the tenant verified domains and run the assessment again.'
                    AutoRemediable = $false
                }
            }
            elseif ($suffix -notin $VerifiedDomain) {
                [pscustomobject]@{
                    Severity = 'Blocking'; Object = $label; Attribute = 'userPrincipalName'
                    Detail = "The suffix '$suffix' is not verified in the tenant. This object will sync, and its sign-in name will be silently rewritten to the tenant's default domain -- so the symptom is a user who cannot sign in with the address on their business card, not a sync error."
                    Remediation = "Add and verify '$suffix' in the tenant, or change the userPrincipalName to a verified suffix."
                    AutoRemediable = $false
                }
            }
        }

        $illegal = @($script:IllegalUpnCharacters | Where-Object { $upn.Contains($_) })
        if ($illegal.Count) {
            [pscustomobject]@{
                Severity = 'Blocking'; Object = $label; Attribute = 'userPrincipalName'
                Detail = "'$upn' contains $($illegal.Count) character(s) Entra refuses: $($illegal -join ' ')."
                Remediation = 'Remove the illegal characters from the userPrincipalName.'
                AutoRemediable = $true
            }
        }
    }

    foreach ($attribute in $script:AttributeLimits.Keys) {
        $value = [string](Get-OptionalProperty $Object $attribute)
        if ($value -and $value.Length -gt $script:AttributeLimits[$attribute]) {
            [pscustomobject]@{
                Severity = 'Blocking'; Object = $label; Attribute = $attribute
                Detail = "$attribute is $($value.Length) characters; Entra accepts $($script:AttributeLimits[$attribute])."
                Remediation = "Shorten $attribute to $($script:AttributeLimits[$attribute]) characters or fewer."
                AutoRemediable = $false
            }
        }
    }

    foreach ($address in @(Get-OptionalProperty $Object 'proxyAddresses')) {
        if ([string]::IsNullOrWhiteSpace($address)) { continue }
        if ($address -notmatch '^[A-Za-z0-9]+:.+$') {
            [pscustomobject]@{
                Severity = 'Blocking'; Object = $label; Attribute = 'proxyAddresses'
                Detail = "'$address' has no type prefix. Entra expects entries like SMTP:user@domain, and an untyped value fails the whole object rather than just that address."
                Remediation = 'Prefix the address with its type, or remove it.'
                AutoRemediable = $true
            }
            continue
        }
        if ($address -match '^(?i)smtp:' -and $address -notmatch '^(?i)smtp:[^@\s]+@[^@\s]+\.[^@\s]+$') {
            [pscustomobject]@{
                Severity = 'Blocking'; Object = $label; Attribute = 'proxyAddresses'
                Detail = "'$address' is typed as SMTP but is not a usable mail address."
                Remediation = 'Correct the address or remove the entry.'
                AutoRemediable = $true
            }
        }
    }

    # A disabled account is not exempt from any of the above. Its attributes
    # still occupy the uniqueness namespace, which is the part people are
    # surprised by, so a reminder travels with it rather than a finding.
    $enabled = Get-OptionalProperty $Object 'enabled'
    if ($null -ne $enabled -and -not $enabled) {
        [pscustomobject]@{
            Severity = 'Note'; Object = $label; Attribute = 'enabled'
            Detail = "$label is disabled. It will still sync and still consume its userPrincipalName and addresses, so it can block an enabled account from syncing."
            Remediation = 'Exclude it from sync scope or clear its conflicting attributes, if it is not meant to exist in the cloud.'
            AutoRemediable = $false
        }
    }
}

function Find-DuplicateAttribute {
    <#
        .SYNOPSIS
            Finds the collisions Entra will refuse across the whole set.
        .DESCRIPTION
            Uniqueness cannot be judged one object at a time, which is why this
            is separate from Test-ObjectReadiness. Three things make it less
            obvious than it sounds:

            Addresses need normalising before comparison, or a primary SMTP on
            one object and the same address as an alias on another look like
            different values. See ConvertTo-AddressKey.

            Disabled objects count. Their attributes occupy the same namespace,
            so a long-forgotten leaver can be the reason a current employee
            fails to sync -- and that is a maddening thing to diagnose, because
            the object causing it is invisible in every list anybody thinks to
            check.

            The report names both sides. A duplicate reported against only one
            object sends somebody hunting for the other.
        .PARAMETER Object
            Every object that will be in sync scope.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Object
    )

    $label = {
        param($o)
        $sam = [string](Get-OptionalProperty $o 'sAMAccountName')
        if ($sam) { return $sam }
        $dn = [string](Get-OptionalProperty $o 'distinguishedName')
        if ($dn) { return $dn }
        return '(unidentified object)'
    }

    foreach ($attribute in 'userPrincipalName', 'mail') {
        $seen = @{}
        foreach ($item in $Object) {
            $value = [string](Get-OptionalProperty $item $attribute)
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            $key = $value.ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) { $seen[$key] = @() }
            $seen[$key] += $item
        }

        foreach ($key in ($seen.Keys | Sort-Object)) {
            if ($seen[$key].Count -lt 2) { continue }
            $holders = @($seen[$key] | ForEach-Object { & $label $_ } | Sort-Object)
            $disabled = @($seen[$key] | Where-Object {
                $e = Get-OptionalProperty $_ 'enabled'
                $null -ne $e -and -not $e
            }).Count

            $aside = if ($disabled -gt 0) {
                " $disabled of them is disabled, which does not exempt it: the value is taken either way."
            } else { '' }

            [pscustomobject]@{
                Severity = 'Blocking'; Attribute = $attribute; Value = $key
                Objects = $holders
                Detail = "$($holders.Count) objects share $attribute '$key': $($holders -join ', ').$aside Entra requires this attribute unique, so none of them syncs until one is changed."
            }
        }
    }

    $byAddress = @{}
    foreach ($item in $Object) {
        foreach ($address in @(Get-OptionalProperty $item 'proxyAddresses')) {
            if ([string]::IsNullOrWhiteSpace($address)) { continue }
            $key = ConvertTo-AddressKey $address
            if (-not $byAddress.ContainsKey($key)) { $byAddress[$key] = @() }
            $byAddress[$key] += $item
        }
    }

    foreach ($key in ($byAddress.Keys | Sort-Object)) {
        if ($byAddress[$key].Count -lt 2) { continue }
        $holders = @($byAddress[$key] | ForEach-Object { & $label $_ } | Sort-Object -Unique)
        if ($holders.Count -lt 2) { continue }

        [pscustomobject]@{
            Severity = 'Blocking'; Attribute = 'proxyAddresses'; Value = $key
            Objects = $holders
            Detail = "$($holders.Count) objects claim the address '$key': $($holders -join ', '). Compare the raw values and they may look different -- one holds it as a primary SMTP and another as an alias -- but Entra treats them as the same address and refuses both objects."
        }
    }
}

function Test-DnInScope {
    <#
        .SYNOPSIS
            Decides whether a distinguished name sits under a container.
        .DESCRIPTION
            On component boundaries, not as a substring. "OU=Sales,DC=corp"
            must not capture "OU=NotSales,DC=corp", and a filter written by
            hand catches that far more often than anybody expects because the
            obvious implementation is an EndsWith.
    #>
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [Parameter(Mandatory)][string]$Container
    )

    $dn = $DistinguishedName.Trim()
    $container = $Container.Trim()
    if ($dn -eq $container) { return $true }

    # The comma is what makes this a boundary check rather than a suffix match.
    return $dn.ToLowerInvariant().EndsWith(',' + $container.ToLowerInvariant())
}

function Get-SyncScope {
    <#
        .SYNOPSIS
            Works out which objects a filter configuration actually syncs.
        .DESCRIPTION
            Include rules select, exclude rules remove, and exclusion wins --
            the same precedence Entra applies. An object under no include rule
            is out of scope, so an empty include list syncs nothing rather than
            everything, which is the safer reading of an unconfigured filter
            and the one Entra uses.
        .PARAMETER Object
            Candidate objects.
        .PARAMETER IncludeOu
            Containers whose contents are in scope.
        .PARAMETER ExcludeOu
            Containers removed from scope, applied after includes.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Object,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$IncludeOu,
        [AllowEmptyCollection()][string[]]$ExcludeOu = @()
    )

    $inScope = @()
    foreach ($item in $Object) {
        $dn = [string](Get-OptionalProperty $item 'distinguishedName')
        if ([string]::IsNullOrWhiteSpace($dn)) { continue }

        $included = @($IncludeOu | Where-Object { Test-DnInScope -DistinguishedName $dn -Container $_ }).Count -gt 0
        if (-not $included) { continue }

        $excluded = @($ExcludeOu | Where-Object { Test-DnInScope -DistinguishedName $dn -Container $_ }).Count -gt 0
        if ($excluded) { continue }

        $inScope += $dn
    }

    [pscustomobject]@{
        InScope = @($inScope | Sort-Object)
        Count   = $inScope.Count
    }
}

function Compare-SyncScope {
    <#
        .SYNOPSIS
            Reports what a filter change would do, before it does it.
        .DESCRIPTION
            An object leaving sync scope is not disabled in the cloud. It is
            deleted -- along with its mailbox, its group memberships and its
            licence assignments. Narrowing an OU filter to tidy up a sync is
            therefore one of the most destructive single changes available in a
            hybrid estate, and it looks like housekeeping.

            Entra Connect ships a circuit breaker for this: the export deletion
            threshold, enabled by default at 500, which aborts an export
            carrying more deletions than that before removing anything. It is
            worth knowing precisely what it does and does not cover. It is per
            export, so 499 deletions pass without comment, and a change staged
            across two runs passes twice. Relying on it as the only check means
            relying on a limit nobody in the room chose.

            So this reports the count whatever it is, and grades it against a
            threshold the plan has to state for itself.
        .PARAMETER Before
            Distinguished names in scope under the current configuration.
        .PARAMETER After
            Distinguished names in scope under the proposed configuration.
        .PARAMETER DeletionThreshold
            Deletions above which the change is graded Critical.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Before,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$After,
        [int]$DeletionThreshold = 10
    )

    $afterSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($dn in $After) { [void]$afterSet.Add($dn) }
    $beforeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($dn in $Before) { [void]$beforeSet.Add($dn) }

    $leaving = @($Before | Where-Object { -not $afterSet.Contains($_) } | Sort-Object)
    $arriving = @($After | Where-Object { -not $beforeSet.Contains($_) } | Sort-Object)

    $share = if ($Before.Count -gt 0) { [math]::Round(100.0 * $leaving.Count / $Before.Count, 1) } else { 0 }

    $severity = if ($leaving.Count -eq 0) { 'Info' }
        elseif ($leaving.Count -gt $DeletionThreshold) { 'Critical' }
        else { 'Warning' }

    $detail = if ($leaving.Count -eq 0) {
        "No object leaves scope. $($arriving.Count) would be newly synced."
    }
    else {
        "$($leaving.Count) object(s) leave scope and would be deleted in the cloud, not disabled -- $share% of what is synced today. $($arriving.Count) would be newly synced. Entra Connect's default deletion threshold of 500 would not stop this."
    }

    [pscustomobject]@{
        Severity        = $severity
        DeletedCount    = $leaving.Count
        DeletedShare    = $share
        Deleted         = $leaving
        AddedCount      = $arriving.Count
        Added           = $arriving
        Threshold       = $DeletionThreshold
        Detail          = $detail
    }
}

Export-ModuleMember -Function Test-ObjectReadiness, Find-DuplicateAttribute,
    Get-SyncScope, Compare-SyncScope, Test-DnInScope, ConvertTo-AddressKey

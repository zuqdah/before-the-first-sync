#requires -Version 7.0

<#
    .SYNOPSIS
        Assesses a real forest against what Entra will accept, and checks the
        assessment found exactly the defects that were planted in it.
    .DESCRIPTION
        Runs on the runner, not on the domain controller. The facts come from
        the forest; the judgement lives here, next to the tests that cover it.

        The second half is what makes this a proof rather than a report. A
        check that fires on everything and a check that fires on the right
        things produce identically confident output, so the planted defects are
        declared in lab-objects.json and the assessment is graded against them:
        every declared defect must be found, and the object declared clean must
        produce nothing at all. Missing a defect and inventing one are both
        failures.
    .PARAMETER FactsPath
        Forest facts as exported from the domain controller.
    .PARAMETER PlanPath
        The object set, carrying the declared defects and the scope change.
    .PARAMETER Phase
        'initial' expects every declared defect. 'remediated' expects the
        mechanically fixable ones gone and the judgement calls still present.
    .PARAMETER ReportPath
        Where to write the JSON report.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FactsPath,
    [string]$PlanPath = 'lab-objects.json',
    [ValidateSet('initial', 'remediated')][string]$Phase = 'initial',
    [string]$ReportPath = 'readiness-report.json'
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'
Set-StrictMode -Version Latest

Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'module', 'SyncReadiness', 'SyncReadiness.psm1')) -Force -ErrorAction Stop

# ReadAllText, not Get-Content -Raw. Get-Content decorates its output with ETS
# properties whose object graphs make a deep ConvertTo-Json walk forever.
$facts = [System.IO.File]::ReadAllText($FactsPath) | ConvertFrom-Json
$plan = [System.IO.File]::ReadAllText($PlanPath) | ConvertFrom-Json

$users = @($facts.users)
if (-not $users.Count) { throw 'The forest facts contain no users, so there is nothing to assess.' }
Write-Information "Assessing $($users.Count) objects from $($facts.domain) against verified domains: $($plan.verifiedDomains -join ', ')"

# ---------------------------------------------------------------- assessment
$perObject = foreach ($user in $users) {
    Test-ObjectReadiness -Object $user -VerifiedDomain @($plan.verifiedDomains)
}
$perObject = @($perObject)
$duplicates = @(Find-DuplicateAttribute -Object $users)

$blocking = @($perObject | Where-Object Severity -eq 'Blocking') + @($duplicates | Where-Object Severity -eq 'Blocking')
$unevaluated = @($perObject | Where-Object Severity -eq 'Unevaluated')

Write-Information ''
Write-Information "--- findings ($Phase) ---"
foreach ($finding in ($perObject | Sort-Object Object, Attribute)) {
    Write-Information ("  {0,-12} {1,-18} {2}" -f $finding.Severity, $finding.Object, $finding.Detail)
}
foreach ($finding in $duplicates) {
    Write-Information ("  {0,-12} {1,-18} {2}" -f $finding.Severity, $finding.Attribute, $finding.Detail)
}

# --------------------------------------------------------------- scope change
# The forest root is the DC components only. Taking everything after the first
# comma of an object's distinguished name looks equivalent and is not: for
# CN=user,OU=Staff,DC=corp,DC=local it returns the OU path, so every filter
# built on it came out as OU=Staff,OU=Staff,... and matched nothing. The
# symptom was a scope of zero objects before and after, which reads like a
# configuration with nothing in it rather than like a bug.
$root = (($users[0].distinguishedName -split ',' | Where-Object { $_ -match '^(?i)DC=' }) -join ',')
if (-not $root) { throw "Could not find the forest root in '$($users[0].distinguishedName)'." }

# Organizational unit names resolve to distinguished names through the plan's
# own parent relationships, the same way the forest was built. Service is
# nested under Staff, so assembling OU=Service,<root> by hand would produce a
# container that does not exist and an exclusion that silently does nothing.
$ouDn = @{}
foreach ($ou in $plan.organizationalUnits) {
    $parent = if ($ou.PSObject.Properties['parent'] -and $ou.parent) { $ouDn[$ou.parent] } else { $root }
    if (-not $parent) { throw "OU '$($ou.name)' names parent '$($ou.parent)', which the plan defines later or not at all." }
    $ouDn[$ou.name] = "OU=$($ou.name),$parent"
}

$resolve = {
    param($names)
    @($names | ForEach-Object {
        if (-not $ouDn.ContainsKey($_)) { throw "The scope change names OU '$_', which the plan does not define." }
        $ouDn[$_]
    })
}

$before = Get-SyncScope -Object $users `
    -IncludeOu (& $resolve $plan.scopeChange.before.includeOu) `
    -ExcludeOu (& $resolve $plan.scopeChange.before.excludeOu)
$after = Get-SyncScope -Object $users `
    -IncludeOu (& $resolve $plan.scopeChange.after.includeOu) `
    -ExcludeOu (& $resolve $plan.scopeChange.after.excludeOu)

$scope = Compare-SyncScope -Before $before.InScope -After $after.InScope `
    -DeletionThreshold $plan.scopeChange.deletionThreshold

Write-Information ''
Write-Information '--- scope change ---'
Write-Information "  in scope before: $($before.Count), after: $($after.Count)"
Write-Information "  $($scope.Severity): $($scope.Detail)"

# ------------------------------------------------------------------- grading
$declared = @($plan.users | Where-Object { $_.defect })
$clean = @($plan.users | Where-Object { -not $_.defect })

$found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($finding in $perObject) { [void]$found.Add([string]$finding.Object) }
foreach ($finding in $duplicates) {
    foreach ($object in @($finding.Objects)) { [void]$found.Add([string]$object) }
}

# The mechanically fixable defects are expected to be gone after remediation.
# The judgement calls are expected to remain, and a remediation pass that
# cleared them would mean it had decided something it had no standing to decide.
$mechanical = @('IllegalUpnCharacter', 'UntypedProxyAddress')

$missed = @()
foreach ($user in $declared) {
    $expectedGone = ($Phase -eq 'remediated') -and ($user.defect -in $mechanical)
    $isFound = $found.Contains([string]$user.sam)
    if ($expectedGone -and $isFound) {
        $missed += "$($user.sam): '$($user.defect)' is mechanically fixable and should have been remediated, but is still reported"
    }
    elseif (-not $expectedGone -and -not $isFound) {
        $missed += "$($user.sam): declared defect '$($user.defect)' was not found"
    }
}

$noise = @()
foreach ($user in $clean) {
    if ($found.Contains([string]$user.sam)) {
        $noise += "$($user.sam) is declared clean but was reported. A check that fires on a clean object is noise, and noise is why these reports stop being read."
    }
}

$report = [pscustomobject]@{
    phase       = $Phase
    domain      = $facts.domain
    objectCount = $users.Count
    findings    = $perObject
    duplicates  = $duplicates
    scopeChange = $scope
    summary     = [pscustomobject]@{
        blocking       = $blocking.Count
        unevaluated    = $unevaluated.Count
        declaredDefects = $declared.Count
        missed         = $missed
        noise          = $noise
    }
}

[System.IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 8),
    (New-Object System.Text.UTF8Encoding($false)))

Write-Information ''
Write-Information '--- graded against the planted defects ---'
Write-Information "  $($declared.Count) declared, $($blocking.Count) blocking finding(s), $($unevaluated.Count) unevaluated"
foreach ($line in $missed) { Write-Information "  MISSED: $line" }
foreach ($line in $noise)  { Write-Information "  NOISE:  $line" }

if ($env:GITHUB_STEP_SUMMARY) {
    @(
        "### Readiness assessment ($Phase)"
        ''
        '| | |'
        '|---|---|'
        "| Objects assessed | $($users.Count) |"
        "| Blocking findings | $($blocking.Count) |"
        "| Could not be evaluated | $($unevaluated.Count) |"
        "| Declared defects missed | $($missed.Count) |"
        "| Clean objects wrongly reported | $($noise.Count) |"
        "| Scope change | $($scope.Severity): $($scope.DeletedCount) object(s) would be deleted |"
    ) | Out-File $env:GITHUB_STEP_SUMMARY -Append
}

if ($missed.Count -or $noise.Count) {
    throw "The assessment did not match the planted defects: $($missed.Count) missed, $($noise.Count) false positive(s)."
}

if ($scope.Severity -ne 'Critical') {
    throw "The scope change was graded '$($scope.Severity)'. Narrowing sync scope deletes the objects that fall out of it, and this lab exists to catch that."
}

Write-Information ''
Write-Information "Every declared defect was found, nothing clean was reported, and the scope change was graded Critical."

#requires -Version 7.0
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $modulePath = [System.IO.Path]::Combine($PSScriptRoot, '..', 'module', 'SyncReadiness', 'SyncReadiness.psm1')
    Import-Module $modulePath -Force -ErrorAction Stop

    $script:Verified = @('corp.example.com', 'example.com')

    function New-User {
        param(
            [string]$Sam = 'jsmith',
            [object]$Upn = 'jsmith@corp.example.com',
            [string]$Dn = 'CN=jsmith,OU=Sales,DC=corp,DC=local',
            [object]$Mail = $null,
            [string[]]$ProxyAddresses = @(),
            [object]$Enabled = $true,
            [hashtable]$Extra = @{}
        )
        $o = [ordered]@{
            sAMAccountName    = $Sam
            distinguishedName = $Dn
            proxyAddresses    = $ProxyAddresses
            enabled           = $Enabled
        }
        if ($null -ne $Upn) { $o['userPrincipalName'] = $Upn }
        if ($null -ne $Mail) { $o['mail'] = $Mail }
        foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
        [pscustomobject]$o
    }
}

Describe 'Test-ObjectReadiness' {
    It 'passes a clean object with no findings at all' {
        @(Test-ObjectReadiness -Object (New-User) -VerifiedDomain $script:Verified).Count | Should -Be 0
    }

    It 'blocks a UPN suffix the tenant has not verified' {
        $r = @(Test-ObjectReadiness -Object (New-User -Upn 'jsmith@corp.local') -VerifiedDomain $script:Verified)
        $r.Severity | Should -Contain 'Blocking'
        ($r | Where-Object Attribute -eq 'userPrincipalName').Detail | Should -Match 'not verified'
    }

    # The symptom is a user who cannot sign in, not a sync error, which is why
    # the message says so.
    It 'explains that an unverified suffix is rewritten rather than refused' {
        $r = @(Test-ObjectReadiness -Object (New-User -Upn 'jsmith@corp.local') -VerifiedDomain $script:Verified)
        ($r | Where-Object Attribute -eq 'userPrincipalName').Detail | Should -Match 'silently rewritten'
    }

    # A missing UPN means the suffix check could not run. It must not come back
    # as a passing suffix.
    It 'reports a missing UPN as blocking and says the other checks could not run' {
        $r = @(Test-ObjectReadiness -Object (New-User -Upn $null) -VerifiedDomain $script:Verified)
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'Blocking'
        $r[0].Detail | Should -Match 'cannot be run'
    }

    It 'reports a suffix it could not check as Unevaluated rather than passing it' {
        $r = @(Test-ObjectReadiness -Object (New-User) -VerifiedDomain @())
        $r.Severity | Should -Contain 'Unevaluated'
        ($r | Where-Object Severity -eq 'Unevaluated').Detail | Should -Match 'could not be checked'
    }

    It 'rejects a UPN with no domain part' {
        $r = @(Test-ObjectReadiness -Object (New-User -Upn 'jsmith') -VerifiedDomain $script:Verified)
        ($r | Where-Object Attribute -eq 'userPrincipalName').Detail | Should -Match 'local part and a domain suffix'
    }

    It 'flags illegal characters in a UPN' {
        $r = @(Test-ObjectReadiness -Object (New-User -Upn 'j smith@corp.example.com') -VerifiedDomain $script:Verified)
        ($r | Where-Object { $_.Detail -match 'Entra refuses' }).Count | Should -Be 1
    }

    It 'flags an attribute longer than Entra accepts' {
        $long = 'x' * 25
        $r = @(Test-ObjectReadiness -Object (New-User -Sam $long) -VerifiedDomain $script:Verified)
        ($r | Where-Object Attribute -eq 'sAMAccountName').Detail | Should -Match '25 characters'
    }

    It 'accepts an attribute exactly at the limit' {
        $r = @(Test-ObjectReadiness -Object (New-User -Sam ('x' * 20)) -VerifiedDomain $script:Verified)
        ($r | Where-Object Attribute -eq 'sAMAccountName').Count | Should -Be 0
    }

    It 'rejects a proxy address with no type prefix' {
        $r = @(Test-ObjectReadiness -Object (New-User -ProxyAddresses @('jsmith@example.com')) -VerifiedDomain $script:Verified)
        ($r | Where-Object Attribute -eq 'proxyAddresses').Detail | Should -Match 'no type prefix'
    }

    It 'rejects an SMTP entry that is not a usable address' {
        $r = @(Test-ObjectReadiness -Object (New-User -ProxyAddresses @('SMTP:not-an-address')) -VerifiedDomain $script:Verified)
        ($r | Where-Object Attribute -eq 'proxyAddresses').Detail | Should -Match 'not a usable mail address'
    }

    It 'accepts well-formed primary and secondary addresses' {
        $r = @(Test-ObjectReadiness -Object (New-User -ProxyAddresses @('SMTP:jsmith@example.com', 'smtp:j.smith@example.com')) -VerifiedDomain $script:Verified)
        ($r | Where-Object Attribute -eq 'proxyAddresses').Count | Should -Be 0
    }

    # People assume disabled objects are harmless. They hold their names.
    It 'notes that a disabled object still consumes its identifiers' {
        $r = @(Test-ObjectReadiness -Object (New-User -Enabled $false) -VerifiedDomain $script:Verified)
        ($r | Where-Object Severity -eq 'Note').Detail | Should -Match 'still consume'
    }

    It 'does not treat the note as a blocking finding' {
        $r = @(Test-ObjectReadiness -Object (New-User -Enabled $false) -VerifiedDomain $script:Verified)
        ($r | Where-Object Severity -eq 'Blocking').Count | Should -Be 0
    }
}

Describe 'Find-DuplicateAttribute' {
    It 'finds two objects sharing a UPN and names both' {
        $users = @((New-User -Sam 'a'), (New-User -Sam 'b'))
        $r = @(Find-DuplicateAttribute -Object $users)
        ($r | Where-Object Attribute -eq 'userPrincipalName').Objects | Should -Contain 'a'
        ($r | Where-Object Attribute -eq 'userPrincipalName').Objects | Should -Contain 'b'
    }

    It 'compares UPNs case-insensitively' {
        $users = @((New-User -Sam 'a' -Upn 'JSmith@Corp.Example.com'), (New-User -Sam 'b' -Upn 'jsmith@corp.example.com'))
        @(Find-DuplicateAttribute -Object $users | Where-Object Attribute -eq 'userPrincipalName').Count | Should -Be 1
    }

    # The duplicate a raw string comparison misses entirely.
    It 'matches a primary SMTP against the same address held as an alias' {
        $users = @(
            (New-User -Sam 'a' -Upn 'a@corp.example.com' -ProxyAddresses @('SMTP:Sales@Example.com')),
            (New-User -Sam 'b' -Upn 'b@corp.example.com' -ProxyAddresses @('smtp:sales@example.com'))
        )
        $r = @(Find-DuplicateAttribute -Object $users | Where-Object Attribute -eq 'proxyAddresses')
        $r.Count | Should -Be 1
        $r[0].Detail | Should -Match 'may look different'
    }

    # The leaver nobody thinks to check is the reason the new starter fails.
    It 'counts a disabled object as holding its value, and says so' {
        $users = @(
            (New-User -Sam 'current'),
            (New-User -Sam 'leaver' -Enabled $false)
        )
        $r = @(Find-DuplicateAttribute -Object $users | Where-Object Attribute -eq 'userPrincipalName')
        $r.Count | Should -Be 1
        $r[0].Detail | Should -Match 'disabled, which does not exempt it'
    }

    It 'finds duplicate mail addresses' {
        $users = @(
            (New-User -Sam 'a' -Upn 'a@corp.example.com' -Mail 'shared@example.com'),
            (New-User -Sam 'b' -Upn 'b@corp.example.com' -Mail 'shared@example.com')
        )
        @(Find-DuplicateAttribute -Object $users | Where-Object Attribute -eq 'mail').Count | Should -Be 1
    }

    It 'finds nothing in a clean set' {
        $users = @(
            (New-User -Sam 'a' -Upn 'a@corp.example.com' -ProxyAddresses @('SMTP:a@example.com')),
            (New-User -Sam 'b' -Upn 'b@corp.example.com' -ProxyAddresses @('SMTP:b@example.com'))
        )
        @(Find-DuplicateAttribute -Object $users).Count | Should -Be 0
    }

    It 'does not report an object as duplicating itself' {
        $users = @((New-User -ProxyAddresses @('SMTP:a@example.com', 'smtp:a@example.com')))
        @(Find-DuplicateAttribute -Object $users).Count | Should -Be 0
    }

    It 'handles an empty set' {
        @(Find-DuplicateAttribute -Object @()).Count | Should -Be 0
    }
}

Describe 'Test-DnInScope' {
    It 'matches an object inside the container' {
        Test-DnInScope -DistinguishedName 'CN=a,OU=Sales,DC=corp,DC=local' -Container 'OU=Sales,DC=corp,DC=local' | Should -BeTrue
    }

    It 'matches the container itself' {
        Test-DnInScope -DistinguishedName 'OU=Sales,DC=corp,DC=local' -Container 'OU=Sales,DC=corp,DC=local' | Should -BeTrue
    }

    # The bug an EndsWith implementation always has.
    It 'does not let OU=Sales capture OU=NotSales' {
        Test-DnInScope -DistinguishedName 'CN=a,OU=NotSales,DC=corp,DC=local' -Container 'OU=Sales,DC=corp,DC=local' | Should -BeFalse
    }

    It 'matches nested containers' {
        Test-DnInScope -DistinguishedName 'CN=a,OU=West,OU=Sales,DC=corp,DC=local' -Container 'OU=Sales,DC=corp,DC=local' | Should -BeTrue
    }

    It 'is case-insensitive' {
        Test-DnInScope -DistinguishedName 'CN=a,ou=sales,dc=corp,dc=local' -Container 'OU=Sales,DC=corp,DC=local' | Should -BeTrue
    }
}

Describe 'Get-SyncScope' {
    BeforeAll {
        $script:Objects = @(
            (New-User -Sam 'sales1' -Dn 'CN=sales1,OU=Sales,DC=corp,DC=local'),
            (New-User -Sam 'svc1'   -Dn 'CN=svc1,OU=Service,OU=Sales,DC=corp,DC=local'),
            (New-User -Sam 'hr1'    -Dn 'CN=hr1,OU=HR,DC=corp,DC=local')
        )
    }

    It 'includes only what an include rule selects' {
        $r = Get-SyncScope -Object $script:Objects -IncludeOu @('OU=Sales,DC=corp,DC=local')
        $r.Count | Should -Be 2
        $r.InScope | Should -Not -Contain 'CN=hr1,OU=HR,DC=corp,DC=local'
    }

    It 'lets an exclude rule win over an include' {
        $r = Get-SyncScope -Object $script:Objects `
            -IncludeOu @('OU=Sales,DC=corp,DC=local') -ExcludeOu @('OU=Service,OU=Sales,DC=corp,DC=local')
        $r.Count | Should -Be 1
        $r.InScope[0] | Should -Be 'CN=sales1,OU=Sales,DC=corp,DC=local'
    }

    # An unconfigured filter syncing everything would be the dangerous reading.
    It 'syncs nothing when no include rule is given' {
        (Get-SyncScope -Object $script:Objects -IncludeOu @()).Count | Should -Be 0
    }

    It 'ignores an object with no distinguished name' {
        $objects = $script:Objects + @([pscustomobject]@{ sAMAccountName = 'ghost' })
        (Get-SyncScope -Object $objects -IncludeOu @('DC=corp,DC=local')).Count | Should -Be 3
    }
}

Describe 'Compare-SyncScope' {
    It 'reports an unchanged scope as Info' {
        $r = Compare-SyncScope -Before @('CN=a,OU=X,DC=c,DC=l') -After @('CN=a,OU=X,DC=c,DC=l')
        $r.Severity | Should -Be 'Info'
        $r.DeletedCount | Should -Be 0
    }

    It 'counts objects newly in scope without alarm' {
        $r = Compare-SyncScope -Before @('CN=a,OU=X,DC=c,DC=l') -After @('CN=a,OU=X,DC=c,DC=l', 'CN=b,OU=X,DC=c,DC=l')
        $r.Severity | Should -Be 'Info'
        $r.AddedCount | Should -Be 1
    }

    # The whole reason this function exists.
    It 'says objects leaving scope are deleted, not disabled' {
        $before = 1..5 | ForEach-Object { "CN=u$_,OU=X,DC=c,DC=l" }
        $r = Compare-SyncScope -Before $before -After @('CN=u1,OU=X,DC=c,DC=l')
        $r.DeletedCount | Should -Be 4
        $r.Detail | Should -Match 'deleted in the cloud, not disabled'
    }

    It 'grades a change above the stated threshold as Critical' {
        $before = 1..20 | ForEach-Object { "CN=u$_,OU=X,DC=c,DC=l" }
        $r = Compare-SyncScope -Before $before -After @() -DeletionThreshold 5
        $r.Severity | Should -Be 'Critical'
        $r.DeletedCount | Should -Be 20
    }

    It 'grades a change inside the threshold as Warning rather than passing it' {
        $before = 1..20 | ForEach-Object { "CN=u$_,OU=X,DC=c,DC=l" }
        $after = 1..18 | ForEach-Object { "CN=u$_,OU=X,DC=c,DC=l" }
        $r = Compare-SyncScope -Before $before -After $after -DeletionThreshold 5
        $r.Severity | Should -Be 'Warning'
    }

    It 'reports the share of the estate being removed' {
        $before = 1..10 | ForEach-Object { "CN=u$_,OU=X,DC=c,DC=l" }
        $after = 1..5 | ForEach-Object { "CN=u$_,OU=X,DC=c,DC=l" }
        $r = Compare-SyncScope -Before $before -After $after
        $r.DeletedShare | Should -Be 50
    }

    # 499 deletions pass Entra's default circuit breaker without comment.
    It 'names the default threshold that would not have caught this' {
        $before = 1..20 | ForEach-Object { "CN=u$_,OU=X,DC=c,DC=l" }
        $r = Compare-SyncScope -Before $before -After @()
        $r.Detail | Should -Match 'default deletion threshold of 500 would not stop this'
    }

    It 'handles an empty before set without dividing by zero' {
        $r = Compare-SyncScope -Before @() -After @('CN=a,OU=X,DC=c,DC=l')
        $r.DeletedShare | Should -Be 0
        $r.AddedCount | Should -Be 1
    }

    It 'compares distinguished names case-insensitively' {
        $r = Compare-SyncScope -Before @('CN=a,OU=X,DC=c,DC=l') -After @('cn=a,ou=x,dc=c,dc=l')
        $r.DeletedCount | Should -Be 0
    }
}

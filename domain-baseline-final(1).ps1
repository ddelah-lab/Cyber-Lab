<#
Domain Baseline Script - v5

Purpose:
Collect local workstation information plus selected Active Directory/domain information.
Trimmed version: keeps domain summary/controllers/computers/users/groups/admin-like groups and removes password policy, OUs, trusts, GPOs, local admin members, installed software, hotfixes, and event log settings.
This version avoids RSAT dependency and prefers direct LDAP binding to a supplied DC IP/name plus constructed domain DN when DNS/domain discovery is broken. Process and task-oriented sections include PID/process identifier details where Windows exposes them.

Examples:
    Press Run/Play in PowerShell ISE or VS Code. No arguments are required.
    The script defaults to:
      OutputPath       = .\domain-baseline.txt
      DomainController = 10.159.21.106
      DomainName       = coslab.internal

    Optional command-line override:
    .\domain-baseline-v5-trimmed-v9-pids.ps1 -DomainController 10.159.21.106 -DomainName coslab.internal

Notes:
- Does not require the ActiveDirectory PowerShell module / RSAT.
- Uses the current logged-on credentials for LDAP queries.
- Writes UTF-8.
- If LDAP sections still fail, review the "Domain Connectivity Diagnostics" section first.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location) 'domain-baseline.txt'),

    # 0 means unlimited. Use a number like 100 if the domain is large and you only want a quick sample.
    [int]$MaxItemsPerDomainSection = 0,

    # Keep this off when you need domain info. It is only here for local-only troubleshooting.
    [switch]$SkipDomainSections,

    # Default lab domain. This lets you press Run/Play without passing arguments.
    [string]$DomainName = 'coslab.internal',

    # Default direct LDAP target. This bypasses broken AD DNS discovery in the lab.
    [string]$DomainController = '10.159.21.106',

    # Optional. Use this when the workstation cannot use its current logon token
    # to query AD because DNS/domain discovery is broken. Example:
    # -Credential (Get-Credential COSLAB\student1)
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$OutputFolder = Split-Path -Parent $OutputPath

if ($OutputFolder -and -not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$script:Writer = [System.IO.StreamWriter]::new($OutputPath, $false, $Utf8NoBom)
$script:Writer.AutoFlush = $true
$script:CachedDomainContext = $null

function Add-Line {
    param([AllowNull()][object]$Text = '')

    if ($null -eq $Text) { $Text = '' }
    $StringText = [string]$Text
    Write-Host $StringText
    $script:Writer.WriteLine($StringText)
}

function Add-TextBlock {
    param([AllowNull()][string]$Text = '')

    if ([string]::IsNullOrWhiteSpace($Text)) {
        Add-Line 'No data returned.'
        return
    }

    $Normalized = $Text -replace "`r`n", "`n" -replace "`r", "`n"
    foreach ($Line in ($Normalized -split "`n")) { Add-Line $Line }
}

function Add-Section {
    param([string]$Title)

    Add-Line ''
    Add-Line '============================================================'
    Add-Line $Title
    Add-Line '============================================================'
}

function Add-Command {
    param(
        [Parameter(Mandatory = $true, Position = 0)] [string]$Title,
        [Parameter(Mandatory = $true, Position = 1)] [scriptblock]$Command
    )

    Add-Section $Title

    try {
        $Result = & $Command
        if ($null -eq $Result) {
            Add-Line 'No data returned.'
            return
        }

        $Text = $Result | Out-String -Width 4096
        Add-TextBlock $Text.TrimEnd()
    }
    catch {
        Add-Line ("Unable to collect this section: {0}" -f $_.Exception.Message)
    }
}

function Invoke-CmdText {
    param([Parameter(Mandatory = $true)][string]$CommandLine)

    try {
        cmd.exe /c $CommandLine 2>&1
    }
    catch {
        "Failed to run '$CommandLine': $($_.Exception.Message)"
    }
}

function Test-IsDomainJoined {
    try {
        $ComputerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        return [bool]$ComputerSystem.PartOfDomain
    }
    catch { return $false }
}

function Get-DetectedDomainName {
    if (-not [string]::IsNullOrWhiteSpace($DomainName)) { return $DomainName }

    try {
        $ComputerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($ComputerSystem.PartOfDomain -and -not [string]::IsNullOrWhiteSpace($ComputerSystem.Domain)) {
            return [string]$ComputerSystem.Domain
        }
    }
    catch { }

    if (-not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)) { return $env:USERDNSDOMAIN }
    if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN)) { return $env:USERDOMAIN }
    return ''
}

function Assert-DomainCollectionAllowed {
    if ($SkipDomainSections) { throw 'Domain sections were skipped because -SkipDomainSections was specified.' }
    if (-not (Test-IsDomainJoined)) { throw 'This computer is not domain joined, so Active Directory sections are not available.' }
}

function Get-LdapServerCandidates {
    $Candidates = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
        [void]$Candidates.Add(($DomainController -replace '^\\+', '').Trim())
    }

    if (-not [string]::IsNullOrWhiteSpace($env:LOGONSERVER)) {
        [void]$Candidates.Add(($env:LOGONSERVER -replace '^\\+', '').Trim())
    }

    $DetectedDomain = Get-DetectedDomainName
    if (-not [string]::IsNullOrWhiteSpace($DetectedDomain)) {
        try {
            $NltestOutput = Invoke-CmdText "nltest /dsgetdc:$DetectedDomain"
            foreach ($Line in $NltestOutput) {
                if ($Line -match 'DC:\s+\\\\(?<dc>\S+)') { [void]$Candidates.Add($Matches.dc.Trim()) }
                if ($Line -match 'Address:\s+\\\\(?<ip>\S+)') { [void]$Candidates.Add($Matches.ip.Trim()) }
            }
        }
        catch { }

        [void]$Candidates.Add($DetectedDomain.Trim())
    }

    # Last resort: try default RootDSE bind without an explicit server.
    [void]$Candidates.Add('')

    $Candidates |
        Where-Object { $null -ne $_ } |
        ForEach-Object { ([string]$_).Trim() } |
        Where-Object { $_ -ne '.' } |
        Select-Object -Unique
}

function Convert-DomainNameToDistinguishedName {
    param([AllowNull()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }

    $CleanName = $Name.Trim()
    if ($CleanName -like 'DC=*') { return $CleanName }

    # Prefer the DNS-style domain name. A NetBIOS name like COSLAB is not enough
    # to build a reliable LDAP search base unless USERDNSDOMAIN is also present.
    if ($CleanName -notmatch '\.' -and -not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)) {
        $CleanName = $env:USERDNSDOMAIN.Trim()
    }

    if ($CleanName -notmatch '\.') { return '' }

    return (($CleanName -split '\.') | Where-Object { $_ } | ForEach-Object { "DC=$_" }) -join ','
}

function Get-DirectoryValue {
    param(
        [Parameter(Mandatory = $true)] [object]$DirectoryEntry,
        [Parameter(Mandatory = $true)] [string]$PropertyName
    )

    # DirectoryEntry sometimes does not populate RootDSE operational attributes
    # until RefreshCache/InvokeGet is used. The old version treated that as an
    # empty value, which caused every domain section to fail.
    try {
        try { $DirectoryEntry.RefreshCache(@($PropertyName)) } catch { }

        $Property = $DirectoryEntry.Properties[$PropertyName]
        if ($null -ne $Property -and $Property.Count -ge 1) { return [string]$Property[0] }

        try {
            $InvokeValue = $DirectoryEntry.InvokeGet($PropertyName)
            if ($null -ne $InvokeValue) { return [string]$InvokeValue }
        }
        catch { }

        return ''
    }
    catch { return '' }
}


function New-AdDirectoryEntry {
    param(
        [Parameter(Mandatory = $true)] [string]$Path
    )

    if ($Credential) {
        return [System.DirectoryServices.DirectoryEntry]::new(
            $Path,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password,
            [System.DirectoryServices.AuthenticationTypes]::Secure
        )
    }

    return [System.DirectoryServices.DirectoryEntry]::new($Path)
}

function Get-CredentialStatusText {
    if ($Credential) { return "Explicit credential supplied: $($Credential.UserName)" }
    return 'Using current logon credentials'
}

function Get-DomainContext {
    Assert-DomainCollectionAllowed
    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop

    if ($script:CachedDomainContext) { return $script:CachedDomainContext }

    $Errors = New-Object System.Collections.Generic.List[string]
    $FallbackDefaultNamingContext = Convert-DomainNameToDistinguishedName (Get-DetectedDomainName)

    foreach ($Server in (Get-LdapServerCandidates)) {
        try {
            $ServerLabel = if ([string]::IsNullOrWhiteSpace($Server)) { '<default>' } else { $Server }

            # IMPORTANT LAB WORKAROUND:
            # If -DomainController is an IP/name and -DomainName is available, try the
            # exact direct-bind method first:
            #   LDAP://10.159.21.106/DC=coslab,DC=internal
            # This avoids RootDSE, nltest, SRV lookup, and domain DNS discovery.
            if (-not [string]::IsNullOrWhiteSpace($Server) -and -not [string]::IsNullOrWhiteSpace($FallbackDefaultNamingContext)) {
                $DirectDomainPath = "LDAP://$Server/$FallbackDefaultNamingContext"
                try {
                    $DirectDomainRoot = New-AdDirectoryEntry -Path $DirectDomainPath
                    $null = $DirectDomainRoot.NativeObject

                    # Prove the search path works with the same simple one-user test you ran manually.
                    $DirectSearcher = [System.DirectoryServices.DirectorySearcher]::new($DirectDomainRoot)
                    $DirectSearcher.Filter = '(&(objectCategory=person)(objectClass=user))'
                    $DirectSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                    $DirectSearcher.PageSize = 1000
                    [void]$DirectSearcher.PropertiesToLoad.Add('sAMAccountName')
                    $DirectSmoke = $DirectSearcher.FindOne()

                    $Context = [pscustomobject]@{
                        Server                         = $Server
                        RootDsePath                    = 'Skipped'
                        DomainPath                     = $DirectDomainPath
                        DefaultNamingContext           = $FallbackDefaultNamingContext
                        ConfigurationNamingContext     = "CN=Configuration,$FallbackDefaultNamingContext"
                        SchemaNamingContext            = "CN=Schema,CN=Configuration,$FallbackDefaultNamingContext"
                        NamingContextSource            = 'Direct LDAP bind using DomainController + constructed DomainName DN; RootDSE/SRV discovery bypassed'
                        DnsHostName                    = ''
                        DomainFunctionality            = ''
                        ForestFunctionality            = ''
                        HighestCommittedUSN            = ''
                        DetectedDomainName             = Get-DetectedDomainName
                        UserDnsDomain                  = $env:USERDNSDOMAIN
                        UserDomain                     = $env:USERDOMAIN
                        LogonServer                    = $env:LOGONSERVER
                        DnsWarning                     = 'Using direct LDAP target, so AD DNS discovery is bypassed for collection.'
                    }

                    if ($DirectSearcher) { $DirectSearcher.Dispose() }
                    $script:CachedDomainContext = $Context
                    return $Context
                }
                catch {
                    [void]$Errors.Add("$ServerLabel direct domain bind/search $DirectDomainPath failed: $($_.Exception.Message)")
                    # Continue to RootDSE path below as a fallback.
                }
            }

            $RootPath = if ([string]::IsNullOrWhiteSpace($Server)) { 'LDAP://RootDSE' } else { "LDAP://$Server/RootDSE" }
            $RootDse = New-AdDirectoryEntry -Path $RootPath

            # Force bind/read now so failures are caught here.
            try { $null = $RootDse.NativeObject } catch { throw "RootDSE bind failed for ${RootPath}: $($_.Exception.Message)" }

            $DefaultNamingContext = Get-DirectoryValue -DirectoryEntry $RootDse -PropertyName 'defaultNamingContext'
            $ConfigurationNamingContext = Get-DirectoryValue -DirectoryEntry $RootDse -PropertyName 'configurationNamingContext'
            $SchemaNamingContext = Get-DirectoryValue -DirectoryEntry $RootDse -PropertyName 'schemaNamingContext'

            # Some lab images / DNS setups return an empty RootDSE even though the
            # machine is domain joined. In that case, build the naming context from
            # the DNS domain and validate it by binding directly to that DN.
            $UsedConstructedNamingContext = $false
            if ([string]::IsNullOrWhiteSpace($DefaultNamingContext) -and -not [string]::IsNullOrWhiteSpace($FallbackDefaultNamingContext)) {
                $DefaultNamingContext = $FallbackDefaultNamingContext
                $ConfigurationNamingContext = "CN=Configuration,$DefaultNamingContext"
                $SchemaNamingContext = "CN=Schema,$ConfigurationNamingContext"
                $UsedConstructedNamingContext = $true
            }

            if ([string]::IsNullOrWhiteSpace($DefaultNamingContext)) {
                throw "RootDSE bind succeeded but defaultNamingContext was empty for $RootPath, and no DNS domain was available to construct a fallback naming context"
            }

            $DomainPath = if ([string]::IsNullOrWhiteSpace($Server)) { "LDAP://$DefaultNamingContext" } else { "LDAP://$Server/$DefaultNamingContext" }
            try {
                $DomainRoot = New-AdDirectoryEntry -Path $DomainPath
                $null = $DomainRoot.NativeObject
            }
            catch {
                throw "Could not bind to domain naming context $DomainPath after RootDSE discovery/fallback: $($_.Exception.Message)"
            }

            $Context = [pscustomobject]@{
                Server                         = $Server
                RootDsePath                    = $RootPath
                DomainPath                     = $DomainPath
                DefaultNamingContext           = $DefaultNamingContext
                ConfigurationNamingContext     = $ConfigurationNamingContext
                SchemaNamingContext            = $SchemaNamingContext
                NamingContextSource            = $(if ($UsedConstructedNamingContext) { 'Constructed from detected DNS domain because RootDSE was empty' } else { 'RootDSE' })
                DnsHostName                    = Get-DirectoryValue -DirectoryEntry $RootDse -PropertyName 'dnsHostName'
                DomainFunctionality            = Get-DirectoryValue -DirectoryEntry $RootDse -PropertyName 'domainFunctionality'
                ForestFunctionality            = Get-DirectoryValue -DirectoryEntry $RootDse -PropertyName 'forestFunctionality'
                HighestCommittedUSN            = Get-DirectoryValue -DirectoryEntry $RootDse -PropertyName 'highestCommittedUSN'
                DetectedDomainName             = Get-DetectedDomainName
                UserDnsDomain                  = $env:USERDNSDOMAIN
                UserDomain                     = $env:USERDOMAIN
                LogonServer                    = $env:LOGONSERVER
                DnsWarning                     = $(if ((Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses }) -notcontains ($Server -replace '^\+', '')) { 'If domain discovery still fails, set the workstation DNS server to the DC/domain DNS, not pfSense/home DNS.' } else { '' })
            }

            $script:CachedDomainContext = $Context
            return $Context
        }
        catch {
            $Label = if ([string]::IsNullOrWhiteSpace($Server)) { '<default>' } else { $Server }
            [void]$Errors.Add("$Label : $($_.Exception.Message)")
        }
    }


    throw "Unable to bind to LDAP. Tried: $($Errors -join ' | ')"
}

function New-DomainSearcher {
    param(
        [Parameter(Mandatory = $true)] [string]$SearchBase,
        [Parameter(Mandatory = $true)] [string]$Filter,
        [string[]]$PropertiesToLoad = @(),
        [string]$SearchScope = 'Subtree'
    )

    $Context = Get-DomainContext
    $LdapPath = if ([string]::IsNullOrWhiteSpace($Context.Server)) {
        "LDAP://$SearchBase"
    }
    else {
        "LDAP://$($Context.Server)/$SearchBase"
    }

    $DirectoryEntry = New-AdDirectoryEntry -Path $LdapPath
    $Searcher = [System.DirectoryServices.DirectorySearcher]::new($DirectoryEntry)
    $Searcher.Filter = $Filter
    $Searcher.PageSize = 1000
    $Searcher.SizeLimit = 0
    $Searcher.SearchScope = [System.DirectoryServices.SearchScope]::$SearchScope

    foreach ($Property in $PropertiesToLoad) { [void]$Searcher.PropertiesToLoad.Add($Property) }
    return $Searcher
}

function Convert-LargeIntegerToInt64 {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [int64] -or $Value -is [int] -or $Value -is [long]) { return [int64]$Value }

    try {
        $High = $Value.HighPart
        $Low = $Value.LowPart
        if ($Low -lt 0) { $Low = $Low + 4294967296 }
        return ([int64]$High -shl 32) -bor ([int64]$Low)
    }
    catch { }

    try { return [int64]$Value } catch { return $null }
}

function Convert-FileTimeValue {
    param([AllowNull()][object]$Value)

    $IntValue = Convert-LargeIntegerToInt64 $Value
    if ($null -eq $IntValue -or $IntValue -le 0 -or $IntValue -ge 9223372036854775807) { return '' }

    try { return [DateTime]::FromFileTimeUtc($IntValue).ToString('yyyy-MM-dd HH:mm:ssZ') }
    catch { return [string]$Value }
}

function Convert-DurationValue {
    param([AllowNull()][object]$Value)

    $IntValue = Convert-LargeIntegerToInt64 $Value
    if ($null -eq $IntValue -or $IntValue -eq 0) { return '' }

    try {
        # AD stores many domain policy durations as negative 100-nanosecond intervals.
        $Ticks = [Math]::Abs($IntValue)
        return ([TimeSpan]::FromTicks($Ticks)).ToString()
    }
    catch { return [string]$Value }
}

function Convert-LdapValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [byte[]]) { return [System.BitConverter]::ToString($Value) }
    return [string]$Value
}

function Convert-LdapProperty {
    param(
        [Parameter(Mandatory = $true)] [object]$Properties,
        [Parameter(Mandatory = $true)] [string]$Name
    )

    $Key = $Name.ToLowerInvariant()

    try {
        if (-not $Properties.Contains($Key)) { return '' }
        $Values = @($Properties[$Key])
        if ($Values.Count -eq 0) { return '' }
        $Converted = foreach ($Value in $Values) { Convert-LdapValue $Value }
        return ($Converted -join '; ')
    }
    catch { return '' }
}

function Get-DomainItems {
    param(
        [Parameter(Mandatory = $true)] [string]$Filter,
        [Parameter(Mandatory = $true)] [string[]]$Properties,
        [string]$SearchBase,
        [string]$SearchScope = 'Subtree'
    )

    $Context = Get-DomainContext
    if ([string]::IsNullOrWhiteSpace($SearchBase)) { $SearchBase = $Context.DefaultNamingContext }

    $Searcher = New-DomainSearcher -SearchBase $SearchBase -Filter $Filter -PropertiesToLoad $Properties -SearchScope $SearchScope
    $Results = $null

    try {
        $Results = $Searcher.FindAll()
        $Count = 0

        foreach ($Result in $Results) {
            if ($MaxItemsPerDomainSection -gt 0 -and $Count -ge $MaxItemsPerDomainSection) { break }

            $Object = [ordered]@{}
            foreach ($Property in $Properties) {
                if ($Property -ieq 'enabled') {
                    $UacRaw = Convert-LdapProperty -Properties $Result.Properties -Name 'useraccountcontrol'
                    if ($UacRaw -match '^\d+$') { $Object[$Property] = -not (([int]$UacRaw -band 2) -eq 2) }
                    else { $Object[$Property] = '' }
                    continue
                }

                $Value = Convert-LdapProperty -Properties $Result.Properties -Name $Property
                switch -Regex ($Property) {
                    '^(lastlogontimestamp|pwdlastset|lastlogon|badpasswordtime|accountexpires)$' { $Value = Convert-FileTimeValue $Value }
                    '^(maxpwdage|minpwdage|lockoutduration|lockoutobservationwindow)$' { $Value = Convert-DurationValue $Value }
                }

                $Object[$Property] = $Value
            }

            [pscustomobject]$Object
            $Count++
        }
    }
    finally {
        if ($Results) { $Results.Dispose() }
        if ($Searcher) { $Searcher.Dispose() }
    }
}


function Get-CnFromDistinguishedName {
    param([AllowNull()][string]$DistinguishedName)

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return '' }

    $FirstPart = ($DistinguishedName -split ',')[0]
    if ($FirstPart -match '^CN=(?<cn>.*)$') {
        return ($Matches.cn -replace '\\,', ',')
    }

    return $DistinguishedName
}

function Convert-SemicolonListToNames {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }

    return @(
        $Value -split '; ' |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { Get-CnFromDistinguishedName $_ }
    )
}

function Get-DomainGroupsFormatted {
    $Groups = Get-DomainItems '(&(objectCategory=group))' @(
        'samaccountname',
        'name',
        'grouptype',
        'description',
        'member',
        'whencreated',
        'whenchanged',
        'distinguishedname'
    ) | Sort-Object samaccountname

    foreach ($Group in $Groups) {
        $Members = @(Convert-SemicolonListToNames $Group.member)
        $MemberText = if ($Members.Count -gt 0) { ($Members -join "`n  - ") } else { 'None / not readable' }

        [pscustomobject]@{
            GroupName         = $Group.samaccountname
            DisplayName       = $Group.name
            Description       = $Group.description
            MemberCount       = $Members.Count
            Members           = if ($Members.Count -gt 0) { "- $MemberText" } else { $MemberText }
            WhenCreated       = $Group.whencreated
            WhenChanged       = $Group.whenchanged
            DistinguishedName = $Group.distinguishedname
        }
    }
}

function Get-DomainAdminLikeGroupsFormatted {
    $Groups = Get-DomainItems '(|(samAccountName=Domain Admins)(samAccountName=Enterprise Admins)(samAccountName=Schema Admins)(samAccountName=Administrators)(samAccountName=Account Operators)(samAccountName=Server Operators)(samAccountName=Backup Operators)(samAccountName=Group Policy Creator Owners))' @(
        'samaccountname',
        'name',
        'member',
        'distinguishedname'
    ) | Sort-Object samaccountname

    foreach ($Group in $Groups) {
        $Members = @(Convert-SemicolonListToNames $Group.member)
        $MemberText = if ($Members.Count -gt 0) { ($Members -join "`n  - ") } else { 'None / not readable' }

        [pscustomobject]@{
            GroupName         = $Group.samaccountname
            DisplayName       = $Group.name
            MemberCount       = $Members.Count
            Members           = if ($Members.Count -gt 0) { "- $MemberText" } else { $MemberText }
            DistinguishedName = $Group.distinguishedname
        }
    }
}

function Get-DomainPolicyFromLdap {
    $Context = Get-DomainContext
    Get-DomainItems '(objectClass=domainDNS)' @(
        'distinguishedname',
        'minpwdlength',
        'pwdhistorylength',
        'maxpwdage',
        'minpwdage',
        'lockoutthreshold',
        'lockoutduration',
        'lockoutobservationwindow',
        'forceLogoff',
        'whencreated',
        'whenchanged'
    ) -SearchBase $Context.DefaultNamingContext -SearchScope 'Base'
}

function Get-DomainNetAccounts {
    $DetectedDomain = Get-DetectedDomainName
    $Output = New-Object System.Collections.Generic.List[string]
    [void]$Output.Add('LDAP-derived domain policy:')
    [void]$Output.Add(((Get-DomainPolicyFromLdap | Format-List | Out-String -Width 4096).TrimEnd()))
    [void]$Output.Add('')
    [void]$Output.Add('net accounts /domain output, if available:')
    [void]$Output.AddRange([string[]](Invoke-CmdText 'net accounts /domain'))
    if ($DetectedDomain) {
        [void]$Output.Add('')
        [void]$Output.Add("nltest /dsgetdc:$DetectedDomain output:")
        [void]$Output.AddRange([string[]](Invoke-CmdText "nltest /dsgetdc:$DetectedDomain"))
    }
    return $Output
}

function Get-DomainTrustsInfo {
    $Context = Get-DomainContext
    $SystemBase = "CN=System,$($Context.DefaultNamingContext)"
    Get-DomainItems '(objectClass=trustedDomain)' @(
        'cn',
        'name',
        'flatname',
        'trustdirection',
        'trusttype',
        'trustattributes',
        'securityidentifier',
        'distinguishedname'
    ) -SearchBase $SystemBase
}

function Get-AdministratorsGroupName {
    try {
        $Sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        $Account = $Sid.Translate([System.Security.Principal.NTAccount]).Value
        if ($Account) { return ($Account -replace '^.*\\', '') }
        return 'Administrators'
    }
    catch { return 'Administrators' }
}

function Get-LocalAdministrators {
    $GroupName = Get-AdministratorsGroupName

    try {
        Get-LocalGroupMember -Group $GroupName -ErrorAction Stop |
            Sort-Object Name |
            Select-Object Name, ObjectClass, PrincipalSource, SID
    }
    catch {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
        $GroupPath = "WinNT://{0}/{1},group" -f $env:COMPUTERNAME, $GroupName
        $Group = [System.DirectoryServices.DirectoryEntry]::new($GroupPath)

        $Group.Invoke('Members') | ForEach-Object {
            $Member = $_
            $MemberType = $Member.GetType()
            $Name = $MemberType.InvokeMember('Name', 'GetProperty', $null, $Member, $null)
            $Class = $MemberType.InvokeMember('Class', 'GetProperty', $null, $Member, $null)

            [pscustomobject]@{
                Name            = $Name
                ObjectClass     = $Class
                PrincipalSource = 'WinNT'
                SID             = ''
            }
        } | Sort-Object Name
    }
}

function Get-EventLogSettingsSafe {
    foreach ($Log in @('Application', 'Security', 'System', 'Windows PowerShell')) {
        try {
            Get-WinEvent -ListLog $Log -ErrorAction Stop |
                Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes
        }
        catch {
            [pscustomobject]@{
                LogName             = $Log
                IsEnabled           = 'Unable to read'
                LogMode             = $_.Exception.Message
                MaximumSizeInBytes  = ''
            }
        }
    }
}

try {
    Add-Section 'Baseline Report'
    Add-Line ("Generated On : {0}" -f (Get-Date))
    Add-Line ("Computer     : {0}" -f $env:COMPUTERNAME)
    Add-Line ("User         : {0}" -f (whoami))
    Add-Line ("Output File  : {0}" -f $OutputPath)
    Add-Line ("Detected Domain : {0}" -f (Get-DetectedDomainName))
    Add-Line ("Requested DC : {0}" -f $(if ($DomainController) { $DomainController } else { 'Auto' }))
    Add-Line ("LDAP Credentials : {0}" -f (Get-CredentialStatusText))
    Add-Line ("Domain Scan  : {0}" -f $(if ($SkipDomainSections) { 'Skipped by parameter' } elseif (Test-IsDomainJoined) { 'Enabled' } else { 'Skipped because machine is not domain joined' }))
    Add-Line ("Max Domain Items Per Section : {0}" -f $(if ($MaxItemsPerDomainSection -gt 0) { $MaxItemsPerDomainSection } else { 'Unlimited' }))

    Add-Command 'Computer Information' {
        Get-CimInstance Win32_ComputerSystem -ErrorAction Stop |
            Select-Object Name, Domain, PartOfDomain, Manufacturer, Model

        Get-CimInstance Win32_OperatingSystem -ErrorAction Stop |
            Select-Object Caption, Version, BuildNumber, OSArchitecture
    }

    Add-Command 'IP Addresses' {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -notlike '169.254.*' } |
            Sort-Object InterfaceAlias, IPAddress |
            Select-Object InterfaceAlias, IPAddress, PrefixLength
    }

    Add-Command 'DNS Client Configuration' {
        Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Sort-Object InterfaceAlias |
            Select-Object InterfaceAlias, ServerAddresses
    }

    Add-Command 'Network Adapters' {
        Get-NetAdapter -ErrorAction Stop |
            Sort-Object Name |
            Select-Object Name, Status, MacAddress, LinkSpeed
    }

    Add-Command 'Domain Connectivity Diagnostics' {
        $DetectedDomain = Get-DetectedDomainName
        $Output = New-Object System.Collections.Generic.List[string]
        [void]$Output.Add("DetectedDomain: $DetectedDomain")
        [void]$Output.Add("USERDOMAIN: $env:USERDOMAIN")
        [void]$Output.Add("USERDNSDOMAIN: $env:USERDNSDOMAIN")
        [void]$Output.Add("LOGONSERVER: $env:LOGONSERVER")
        [void]$Output.Add("LDAP Credentials: $(Get-CredentialStatusText)")
        [void]$Output.Add('')
        [void]$Output.Add('Note: Your DNS client servers should normally include a domain DNS/DC for AD discovery. If this shows pfSense/home DNS only, nltest and SRV lookups can fail even when cached logon/domain membership exists.')
        [void]$Output.Add('')
        [void]$Output.Add('LDAP candidates:')
        [void]$Output.AddRange([string[]](Get-LdapServerCandidates | ForEach-Object { if ($_ -eq '') { '<default>' } else { $_ } }))
        [void]$Output.Add('')
        [void]$Output.Add('Direct LDAP bind/search smoke test:')
        try {
            $Context = Get-DomainContext
            $Searcher = New-DomainSearcher -SearchBase $Context.DefaultNamingContext -Filter '(objectClass=domainDNS)' -PropertiesToLoad @('distinguishedName') -SearchScope 'Base'
            $Smoke = $Searcher.FindOne()
            if ($Smoke) { [void]$Output.Add("Success: $($Context.DomainPath)") }
            else { [void]$Output.Add("Bind succeeded but base search returned no result: $($Context.DomainPath)") }
        }
        catch {
            [void]$Output.Add("Failed: $($_.Exception.Message)")
        }
        if ($DetectedDomain) {
            [void]$Output.Add('')
            [void]$Output.Add("nltest /dsgetdc:${DetectedDomain}:")
            [void]$Output.AddRange([string[]](Invoke-CmdText "nltest /dsgetdc:$DetectedDomain"))
            [void]$Output.Add('')
            [void]$Output.Add("nslookup -type=SRV _ldap._tcp.dc._msdcs.${DetectedDomain}:")
            [void]$Output.AddRange([string[]](Invoke-CmdText "nslookup -type=SRV _ldap._tcp.dc._msdcs.$DetectedDomain"))
        }
        return $Output
    }

    Add-Command 'Domain Summary' {
        Get-DomainContext | Format-List
    }


    Add-Command 'Domain Controllers' {
        Get-DomainItems '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @(
            'name',
            'dnshostname',
            'operatingsystem',
            'operatingsystemversion',
            'serverreferencebl',
            'lastlogontimestamp',
            'whencreated',
            'whenchanged',
            'distinguishedname'
        ) | Sort-Object name | Format-Table -AutoSize
    }



    Add-Command 'Domain Computers' {
        Get-DomainItems '(&(objectCategory=computer))' @(
            'name',
            'dnshostname',
            'operatingsystem',
            'operatingsystemversion',
            'useraccountcontrol',
            'enabled',
            'lastlogontimestamp',
            'whencreated',
            'whenchanged',
            'distinguishedname'
        ) | Sort-Object name | Format-Table -AutoSize
    }

    Add-Command 'Domain Users' {
        Get-DomainItems '(&(objectCategory=person)(objectClass=user))' @(
            'samaccountname',
            'userprincipalname',
            'name',
            'displayname',
            'mail',
            'enabled',
            'useraccountcontrol',
            'pwdlastset',
            'lastlogontimestamp',
            'whencreated',
            'whenchanged',
            'distinguishedname'
        ) | Sort-Object samaccountname | Format-Table -AutoSize
    }

    Add-Command 'Domain Groups' {
        Get-DomainGroupsFormatted | Format-List
    }


    Add-Command 'Domain Admin-Like Groups' {
        Get-DomainAdminLikeGroupsFormatted | Format-List
    }

    Add-Command 'Local Users' {
        Get-LocalUser -ErrorAction Stop |
            Sort-Object Name |
            Select-Object Name, Enabled, SID, Description
    }

    Add-Command 'Local Groups' {
        Get-LocalGroup -ErrorAction Stop |
            Sort-Object Name |
            Select-Object Name, SID, Description
    }


    Add-Command 'Running Processes' {
        Get-CimInstance Win32_Process -ErrorAction Stop |
            Sort-Object Name, ProcessId |
            Select-Object `
                @{Name = 'ProcessName'; Expression = { $_.Name } },
                @{Name = 'PID'; Expression = { $_.ProcessId } },
                @{Name = 'ParentPID'; Expression = { $_.ParentProcessId } },
                @{Name = 'SessionId'; Expression = { $_.SessionId } }
    }

    Add-Command 'Services' {
        Get-CimInstance Win32_Service -ErrorAction Stop |
            Where-Object { $_.State -ne 'Stopped' } |
            Sort-Object Name |
            Select-Object `
                Name,
                DisplayName,
                State,
                StartMode,
                StartName,
                @{Name = 'PID'; Expression = { $_.ProcessId } }
    }

    Add-Command 'Listening TCP Ports' {
        $ProcessesByPid = @{}
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            $ProcessesByPid[[int]$_.ProcessId] = $_.Name
        }

        Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Sort-Object LocalPort, LocalAddress |
            Select-Object `
                LocalAddress,
                LocalPort,
                @{Name = 'PID'; Expression = { $_.OwningProcess } },
                @{Name = 'ProcessName'; Expression = { $ProcessesByPid[[int]$_.OwningProcess] } }
    }




    Add-Section 'Complete'
    Add-Line ("Saved to: {0}" -f $OutputPath)
}
finally {
    if ($script:Writer) { $script:Writer.Dispose() }
}

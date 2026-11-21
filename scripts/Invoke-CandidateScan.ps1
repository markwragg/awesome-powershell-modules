<#
.SYNOPSIS
    Downloads each candidate module from the PowerShell Gallery and statically analyses it, without running any of it.
.DESCRIPTION
    For every module in the candidates file this:

    - Saves the latest published package with Save-PSResource (download and extract only - nothing is imported or run).
    - Reads the module manifest with Import-PowerShellDataFile (restricted language, no code execution) and flags
      manifest settings that run code or load binaries at import time.
    - Runs PSScriptAnalyzer with an explicit settings hashtable. This matters: without -Settings, PSScriptAnalyzer
      looks for a PSScriptAnalyzerSettings.psd1 inside the scanned path, and a malicious package could ship one that
      points CustomRulePath at its own code.
    - Runs a set of regex checks for patterns PSScriptAnalyzer doesn't cover (download cradles, encoded commands,
      large base64 blobs, AV/AMSI tampering, persistence).
    - Inventories bundled binaries.

    Results are written as JSON for the AI review step to explain and for the PR step to report verbatim.
.PARAMETER CandidatesPath
    JSON file produced from Find-NewGalleryModules.ps1 output.
.PARAMETER DownloadPath
    Folder the packages are saved into. Each module ends up in <DownloadPath>/<Name>/<Version>/.
.PARAMETER OutputPath
    Where to write the scan results JSON.
.EXAMPLE
    ./Find-NewGalleryModules.ps1 | ConvertTo-Json | Out-File candidates.json
    ./Invoke-CandidateScan.ps1 -CandidatesPath candidates.json -DownloadPath scan -OutputPath analysis.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CandidatesPath,
    [string]$DownloadPath = 'scan',
    [string]$OutputPath = 'analysis.json',
    [int]$MaxFindingsPerModule = 50
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Install-PSResource -Name PSScriptAnalyzer -Repository PSGallery -TrustRepository -Scope CurrentUser -Quiet
}
Import-Module PSScriptAnalyzer

# Security-relevant PSScriptAnalyzer rules. Reported individually.
$securityRules = @(
    'PSAvoidUsingInvokeExpression'
    'PSAvoidUsingPlainTextForPassword'
    'PSAvoidUsingConvertToSecureStringWithPlainText'
    'PSAvoidUsingUsernameAndPasswordParams'
    'PSUsePSCredentialType'
    'PSAvoidUsingComputerNameHardcoded'
    'PSAvoidUsingAllowUnencryptedAuthentication'
    'PSAvoidUsingBrokenHashAlgorithms'
)

# Patterns PSScriptAnalyzer doesn't look for. These are signals for a human/AI to look at, not verdicts.
$patterns = [ordered]@{
    DownloadCradle      = '(?i)(Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|DownloadString|DownloadData)[^\r\n]*\|\s*(Invoke-Expression|\biex\b)'
    WebClientDownload   = '(?i)\.Download(String|File|Data)\s*\('
    EncodedCommand      = '(?i)-(EncodedCommand|enc|ec)\s+[A-Za-z0-9+/=]{20,}'
    FromBase64          = '(?i)FromBase64String'
    LargeBase64Blob     = '[A-Za-z0-9+/]{400,}={0,2}'
    SecurityTampering   = '(?i)(Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|AmsiUtils|amsiInitFailed|Set-ExecutionPolicy\s+(Bypass|Unrestricted))'
    Persistence         = '(?i)(CurrentVersion\\Run(Once)?\b|Register-ScheduledTask|schtasks(\.exe)?\s+/create|New-Service\b)'
    CredentialAccess    = '(?i)(Get-StoredCredential|CredEnumerate|\\Login Data\b|\.aws\\credentials|\.ssh\\id_|Mimikatz)'
}

$binaryExtensions = '.dll', '.exe', '.so', '.dylib', '.msi', '.sys', '.bin'
$scriptExtensions = '.ps1', '.psm1', '.psd1', '.ps1xml', '.cs'

New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null
$candidates = @(Get-Content -Path $CandidatesPath -Raw | ConvertFrom-Json)

$results = foreach ($candidate in $candidates) {
    $name = $candidate.Name
    $result = [ordered]@{
        Name               = $name
        Downloaded         = $false
        Version            = $null
        SourcePath         = $null
        Error              = $null
        FileCount          = 0
        ScriptFileCount    = 0
        Binaries           = @()
        ManifestFlags      = @()
        SecurityFindings   = @()
        PatternFindings    = @()
        QualityRuleCounts  = [ordered]@{}
        FindingsTruncated  = $false
    }

    # Gallery package ids are restricted to these characters; refuse anything else before using it in a path.
    if ($name -notmatch '^[A-Za-z0-9._-]+$') {
        $result.Error = 'Package name contains unexpected characters; not downloaded.'
        [PSCustomObject]$result
        continue
    }

    try {
        Save-PSResource -Name $name -Repository PSGallery -Path $DownloadPath -TrustRepository -SkipDependencyCheck -Quiet
        $moduleRoot = Get-ChildItem -Path (Join-Path $DownloadPath $name) -Directory | Select-Object -First 1
        if (-not $moduleRoot) { throw 'Package saved but no version folder was found.' }
        $result.Downloaded = $true
        $result.Version = $moduleRoot.Name
        $result.SourcePath = [System.IO.Path]::GetRelativePath((Get-Location).Path, $moduleRoot.FullName)
    }
    catch {
        $result.Error = "Download failed: $($_.Exception.Message)"
        [PSCustomObject]$result
        continue
    }

    $files = @(Get-ChildItem -Path $moduleRoot.FullName -Recurse -File)
    $scriptFiles = @($files | Where-Object { $_.Extension -in $scriptExtensions })
    $result.FileCount = $files.Count
    $result.ScriptFileCount = $scriptFiles.Count
    $result.Binaries = @($files | Where-Object { $_.Extension -in $binaryExtensions } |
        ForEach-Object { [System.IO.Path]::GetRelativePath($moduleRoot.FullName, $_.FullName) })

    # Manifest settings that execute code or load binaries when the module is imported.
    $manifestPath = Join-Path $moduleRoot.FullName "$name.psd1"
    if (Test-Path $manifestPath) {
        try {
            $manifest = Import-PowerShellDataFile -Path $manifestPath
            foreach ($key in 'ScriptsToProcess', 'RequiredAssemblies', 'TypesToProcess', 'FormatsToProcess') {
                if ($manifest.$key) { $result.ManifestFlags += "$key = $(@($manifest.$key) -join ', ')" }
            }
            foreach ($nested in @($manifest.NestedModules) + @($manifest.RootModule)) {
                if ($nested -is [string] -and $nested -match '\.(dll|exe)$') { $result.ManifestFlags += "Binary module: $nested" }
            }
        }
        catch {
            $result.ManifestFlags += "Manifest could not be parsed: $($_.Exception.Message)"
        }
    }
    else {
        $result.ManifestFlags += 'No module manifest found at the package root.'
    }

    $findings = [System.Collections.Generic.List[object]]::new()

    # Explicit settings so PSScriptAnalyzer never picks up a settings file (and custom rules) from the package.
    $analyzerSettings = @{ Severity = @('Error', 'Warning') }
    $diagnostics = @(Invoke-ScriptAnalyzer -Path $moduleRoot.FullName -Recurse -Settings $analyzerSettings -ErrorAction SilentlyContinue)
    foreach ($group in $diagnostics | Group-Object RuleName | Sort-Object Count -Descending) {
        $result.QualityRuleCounts[$group.Name] = $group.Count
    }
    $result.SecurityFindings = @($diagnostics | Where-Object RuleName -in $securityRules | Select-Object -First $MaxFindingsPerModule | ForEach-Object {
            [ordered]@{
                Rule = $_.RuleName
                File = [System.IO.Path]::GetRelativePath($moduleRoot.FullName, $_.ScriptPath)
                Line = $_.Line
            }
        })

    foreach ($file in $scriptFiles) {
        $relative = [System.IO.Path]::GetRelativePath($moduleRoot.FullName, $file.FullName)
        $lineNumber = 0
        foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
            $lineNumber++
            foreach ($patternName in $patterns.Keys) {
                $match = [regex]::Match($line, $patterns[$patternName])
                if ($match.Success) {
                    $snippet = $line.Trim()
                    if ($snippet.Length -gt 160) { $snippet = $snippet.Substring(0, 160) + '...' }
                    $findings.Add([ordered]@{ Pattern = $patternName; File = $relative; Line = $lineNumber; Snippet = $snippet })
                }
            }
        }
    }
    $result.FindingsTruncated = $findings.Count -gt $MaxFindingsPerModule
    $result.PatternFindings = @($findings | Select-Object -First $MaxFindingsPerModule)

    [PSCustomObject]$result
}

ConvertTo-Json -InputObject @($results) -Depth 6 | Out-File -FilePath $OutputPath -Encoding utf8
$results

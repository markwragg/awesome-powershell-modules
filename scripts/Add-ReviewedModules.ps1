<#
.SYNOPSIS
    Applies an AI candidate review to README.md after validating it, and writes the PR body / summary markdown.
.DESCRIPTION
    The review JSON is produced by an AI step that reads untrusted content (module code, READMEs, Gallery pages), so
    this script treats every field in it as untrusted and does not let it decide anything it doesn't have to:

    - Only modules that appear in the candidates file can be added, and their name and URL come from that file, not
      from the review.
    - The category must exactly match an existing "## Contents" heading.
    - The description must be a short, single line of plain text (no links, HTML, mentions or URLs).
    - A module whose package could not be downloaded and scanned, or whose security outcome is Fail or NotReviewed,
      is never added, whatever the review's decision says.
    - Any included module with high-risk static scan hits is listed under "Needs maintainer attention" regardless of
      the review's own security outcome, so the non-AI evidence always reaches a human.
    - Free text from the review is flattened to one line, length-capped, and has @mentions and HTML neutralised before
      it goes into the PR body.

    Entries are inserted alphabetically (culture-invariant, case-insensitive, matching the existing list order).
.PARAMETER CandidatesPath
    JSON produced from Find-NewGalleryModules.ps1.
.PARAMETER AnalysisPath
    JSON produced by Invoke-CandidateScan.ps1.
.PARAMETER ReviewPath
    The AI review's structured output JSON.
.PARAMETER ReadmePath
    README.md to update in place.
.PARAMETER BodyPath
    Where to write the markdown report (used as the PR body, or the step summary if nothing was added).
.OUTPUTS
    The number of modules added to README.md.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CandidatesPath,
    [Parameter(Mandatory)][string]$AnalysisPath,
    [Parameter(Mandatory)][string]$ReviewPath,
    [string]$ReadmePath = (Join-Path $PSScriptRoot '..' 'README.md'),
    [string]$BodyPath = 'report.md'
)

$ErrorActionPreference = 'Stop'

$highRiskPatterns = 'DownloadCradle', 'EncodedCommand', 'SecurityTampering', 'CredentialAccess', 'Persistence', 'LargeBase64Blob'
$comparer = [System.StringComparer]::Create([cultureinfo]::InvariantCulture, $true)

function ConvertTo-SafeText {
    # Flattens untrusted text for the PR body: one line, capped, no HTML, no @mentions, no markdown links.
    param([string]$Text, [int]$MaxLength = 300)
    if (-not $Text) { return '' }
    $clean = ($Text -replace '\s+', ' ').Trim()
    $clean = $clean -replace '[<>]', '' -replace '\]\(', '] (' -replace '@', '@&#8203;'
    if ($clean.Length -gt $MaxLength) { $clean = $clean.Substring(0, $MaxLength) + '...' }
    $clean
}

function Test-ReadmeDescription {
    # Returns $null if valid, otherwise the reason it was rejected.
    param([string]$Description)
    if ([string]::IsNullOrWhiteSpace($Description)) { return 'no description supplied' }
    if ($Description -match '[\r\n]') { return 'description spans multiple lines' }
    if ($Description.Length -gt 250) { return 'description longer than 250 characters' }
    if ($Description -match '[<>\[\]@]|://|\]\(') { return 'description contains links, HTML, or mentions' }
    $null
}

function Get-ScanSummary {
    param($Scan)
    if (-not $Scan) { return 'not scanned' }
    if (-not $Scan.Downloaded) { return "not scanned ($(ConvertTo-SafeText $Scan.Error 150))" }

    $parts = @("v$($Scan.Version), $($Scan.ScriptFileCount) script file(s)")
    if ($Scan.SecurityFindings) {
        $rules = $Scan.SecurityFindings | Group-Object Rule | ForEach-Object { "$($_.Name) x$($_.Count)" }
        $parts += "PSScriptAnalyzer security rules: $($rules -join ', ')"
    }
    if ($Scan.PatternFindings) {
        $hits = $Scan.PatternFindings | Group-Object Pattern | ForEach-Object { "$($_.Name) x$($_.Count)" }
        $parts += "pattern hits: $($hits -join ', ')$(if ($Scan.FindingsTruncated) { ' (truncated)' })"
    }
    if ($Scan.Binaries) { $parts += "$(@($Scan.Binaries).Count) bundled binar$(if (@($Scan.Binaries).Count -eq 1) { 'y' } else { 'ies' })" }
    if ($Scan.ManifestFlags) {
        $flags = $Scan.ManifestFlags | ForEach-Object { ($_ -split ' = ')[0] }
        $parts += "manifest: $(ConvertTo-SafeText ($flags -join ', ') 150)"
    }
    $parts -join '; '
}

function Get-HighRiskReasons {
    param($Scan)
    $reasons = @()
    if (-not $Scan -or -not $Scan.Downloaded) { return $reasons }
    $hits = @($Scan.PatternFindings | Where-Object Pattern -in $highRiskPatterns)
    if ($hits) {
        $reasons += 'static scan pattern hits: ' + (($hits | Group-Object Pattern | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ')
    }
    if ($Scan.SecurityFindings | Where-Object Rule -eq 'PSAvoidUsingInvokeExpression') { $reasons += 'uses Invoke-Expression' }
    if ($Scan.ManifestFlags -match '^ScriptsToProcess') { $reasons += 'manifest runs ScriptsToProcess on import' }
    if ($Scan.Binaries) { $reasons += "ships $(@($Scan.Binaries).Count) binary file(s)" }
    $reasons
}

function Get-ReadmeUrl {
    # Validates the candidate's URL and applies the list's "#readme" convention for GitHub repo roots.
    param([string]$Url)
    $uri = $null
    if (-not [uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https' -or $Url -match '[\s()<>]') {
        return $null
    }
    if ($Url -match '^https://github\.com/[^/]+/[^/#?]+/?$') { return $Url.TrimEnd('/') + '#readme' }
    $Url
}

$candidates = @(Get-Content -Path $CandidatesPath -Raw | ConvertFrom-Json)

# Names are written into README.md and the PR body, so re-check them here rather than relying on the scan job.
$invalidNameCount = @($candidates | Where-Object { $_.Name -notmatch '^[A-Za-z0-9._-]+$' }).Count
$candidates = @($candidates | Where-Object { $_.Name -match '^[A-Za-z0-9._-]+$' })
$analysis = @(Get-Content -Path $AnalysisPath -Raw | ConvertFrom-Json)
$review = Get-Content -Path $ReviewPath -Raw | ConvertFrom-Json
$readme = [System.Collections.Generic.List[string]](Get-Content -Path $ReadmePath)

$scanByName = @{}
foreach ($scan in $analysis) { $scanByName[$scan.Name] = $scan }

$reviewByName = @{}
$unexpected = @()
foreach ($item in @($review.candidates)) {
    $match = $candidates | Where-Object { $_.Name -eq $item.name } | Select-Object -First 1
    if ($match) { $reviewByName[$match.Name] = $item } else { $unexpected += $item.name }
}

# Categories are the "## Contents" entries; only those headings are valid targets.
$contentsStart = $readme.IndexOf('## Contents')
$categories = for ($i = $contentsStart + 1; $i -lt $readme.Count -and $readme[$i] -notmatch '^## '; $i++) {
    if ($readme[$i] -match '^- \[(?<Name>[^\]]+)\]\(#') { $Matches.Name }
}

$existingNames = [regex]::Matches(($readme -join "`n"), '(?m)^- \[(?<Name>[^\]]+)\]\(') | ForEach-Object { $_.Groups['Name'].Value }

$added = [System.Collections.Generic.List[object]]::new()
$notAdded = [System.Collections.Generic.List[object]]::new()
$attention = [System.Collections.Generic.List[string]]::new()

foreach ($candidate in $candidates) {
    $name = $candidate.Name
    $item = $reviewByName[$name]
    $scan = $scanByName[$name]

    $entry = [ordered]@{
        Name     = $name
        Reason   = if ($item) { ConvertTo-SafeText $item.reason } else { 'Not returned by the review.' }
        Security = if ($item) { "$($item.securityOutcome) - $(ConvertTo-SafeText $item.securityEvidence)" } else { 'NotReviewed' }
        Scan     = Get-ScanSummary $scan
    }

    $rejection = $null
    if (-not $item) { $rejection = 'not reviewed' }
    elseif ($item.decision -ne 'include') { $rejection = $null }
    elseif ($item.securityOutcome -notin 'Pass', 'Concerns') { $rejection = "security outcome is $($item.securityOutcome)" }
    elseif (-not $scan -or -not $scan.Downloaded) { $rejection = 'package could not be downloaded and scanned' }
    elseif ($item.category -cnotin $categories) { $rejection = "category '$(ConvertTo-SafeText $item.category 60)' is not an existing category" }
    elseif ($existingNames | Where-Object { $comparer.Equals($_, $name) }) { $rejection = 'already in README.md' }
    elseif ($reason = Test-ReadmeDescription $item.description) { $rejection = $reason }
    elseif (-not ($url = Get-ReadmeUrl $candidate.ProjectUrl)) { $rejection = 'project URL is not a plain https URL' }

    if (-not $item -or $item.decision -ne 'include' -or $rejection) {
        if ($rejection -and $item -and $item.decision -eq 'include') {
            $entry.Reason = "Review recommended inclusion, but it was blocked by validation: $rejection. Review reasoning: $($entry.Reason)"
        }
        $notAdded.Add($entry)
        continue
    }

    $description = $item.description.Trim()
    if ($description -notmatch '[.!?]$') { $description += '.' }
    $line = "- [$name]($url) - $description"

    # Insert alphabetically within the category's section.
    $headingIndex = $readme.IndexOf("## $($item.category)")
    $sectionEnd = $headingIndex + 1
    while ($sectionEnd -lt $readme.Count -and $readme[$sectionEnd] -notmatch '^## ') { $sectionEnd++ }

    $insertAt = $null
    $lastEntry = $null
    for ($i = $headingIndex + 1; $i -lt $sectionEnd; $i++) {
        if ($readme[$i] -match '^- \[(?<Name>[^\]]+)\]') {
            $lastEntry = $i
            if ($null -eq $insertAt -and $comparer.Compare($Matches.Name, $name) -gt 0) { $insertAt = $i }
        }
    }
    if ($null -eq $insertAt) {
        $insertAt = if ($null -ne $lastEntry) { $lastEntry + 1 } else { $headingIndex + 2 }
    }
    $readme.Insert($insertAt, $line)
    $existingNames += $name

    $entry.Category = $item.category
    $added.Add($entry)

    $risks = @(Get-HighRiskReasons $scan)
    if ($item.securityOutcome -eq 'Concerns') { $risks = @("review raised concerns: $(ConvertTo-SafeText $item.securityEvidence)") + $risks }
    if ($risks) { $attention.Add("- **$name** - $($risks -join '; ')") }
}

$body = [System.Text.StringBuilder]::new()
if ($attention.Count) {
    [void]$body.AppendLine('### Needs maintainer attention').AppendLine()
    foreach ($line in $attention) { [void]$body.AppendLine($line) }
    [void]$body.AppendLine()
}
foreach ($section in @(@{ Title = 'Added'; Items = $added }, @{ Title = 'Not added'; Items = $notAdded })) {
    [void]$body.AppendLine("### $($section.Title)").AppendLine()
    if (-not $section.Items.Count) { [void]$body.AppendLine('_None._') }
    foreach ($e in $section.Items) {
        $category = if ($e.Category) { " _($($e.Category))_" } else { '' }
        [void]$body.AppendLine("- **$($e.Name)**$category - $($e.Reason)")
        [void]$body.AppendLine("  - Security review: $($e.Security)")
        [void]$body.AppendLine("  - Static scan: $($e.Scan)")
    }
    [void]$body.AppendLine()
}
if ($unexpected) {
    [void]$body.AppendLine('### Ignored review output').AppendLine()
    [void]$body.AppendLine("The review returned entries for modules that weren't candidates: $(ConvertTo-SafeText ($unexpected -join ', ') 300)")
    [void]$body.AppendLine()
}
if ($invalidNameCount) {
    [void]$body.AppendLine('### Ignored candidates').AppendLine()
    [void]$body.AppendLine("$invalidNameCount candidate(s) had a name with unexpected characters and were skipped.")
    [void]$body.AppendLine()
}
[void]$body.AppendLine('---').AppendLine()
[void]$body.AppendLine('Candidates reviewed by Claude; README edits, validation and this PR were made by `scripts/Add-ReviewedModules.ps1`. Static scan results come from PSScriptAnalyzer and `scripts/Invoke-CandidateScan.ps1`, not the AI review.')

$body.ToString() | Out-File -FilePath $BodyPath -Encoding utf8
if ($added.Count) { $readme | Set-Content -Path $ReadmePath -Encoding utf8 }

$added.Count

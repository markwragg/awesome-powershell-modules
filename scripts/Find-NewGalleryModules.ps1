<#
.SYNOPSIS
    Lists modules first published to the PowerShell Gallery within a given age window that aren't already in README.md, for review as candidates to add to the list.
.DESCRIPTION
    Queries the PowerShell Gallery OData feed directly (no PowerShellGet/PSResourceGet dependency).

    The Gallery rejects unscoped date-range filters on Packages() (e.g. "Created gt datetime'...'"), so instead this
    pages the Search() endpoint, which returns the latest stable version of each module ordered by Published date,
    newest first. Paging stops once it reaches modules last published before the window start: a module whose latest
    version predates the window can't have been first published inside it.

    Every remaining module that isn't already in README.md then gets one small lookup for its earliest-ever version, so
    a module doesn't dodge the window just because it has shipped new versions since. Those lookups run in parallel.
    Metadata (project URL, author, downloads, description) comes from the Search() entry, which is already the latest
    stable release, so no further request is needed.

    The default 30-37 day window is intended to give a new module a little time to mature before it's reviewed,
    while still catching it within the next weekly run.
.PARAMETER MinAgeDays
    Minimum age in days of the module's first-ever published version. Default 30.
.PARAMETER MaxAgeDays
    Maximum age in days of the module's first-ever published version. Default 37.
.PARAMETER Path
    Path to the README.md file used to exclude modules already on the list.
.PARAMETER ThrottleLimit
    Number of earliest-version lookups to run in parallel. Default 8.
.EXAMPLE
    ./Find-NewGalleryModules.ps1 | Format-Table Name, FirstPublished, ProjectUrl
.EXAMPLE
    ./Find-NewGalleryModules.ps1 -MinAgeDays 30 -MaxAgeDays 37 | Sort-Object Downloads -Descending
#>
[CmdletBinding()]
param(
    [int]$MinAgeDays = 30,
    [int]$MaxAgeDays = 37,
    [string]$Path = (Join-Path $PSScriptRoot '..' 'README.md'),
    [int]$ThrottleLimit = 8
)

$ErrorActionPreference = 'Stop'

$galleryApi = 'https://www.powershellgallery.com/api/v2'
$pageSize = 100

$ns = @{
    a = 'http://www.w3.org/2005/Atom'
    d = 'http://schemas.microsoft.com/ado/2007/08/dataservices'
    m = 'http://schemas.microsoft.com/ado/2007/08/dataservices/metadata'
}

function Get-NormalizedName {
    param([string]$Name)
    ($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
}

function Get-GalleryFeedPage {
    param([string]$Uri)

    $response = Invoke-WebRequest -Uri $Uri -MaximumRetryCount 3 -RetryIntervalSec 5
    [xml]$feed = $response.Content

    $nsMgr = [System.Xml.XmlNamespaceManager]::new($feed.NameTable)
    foreach ($key in $ns.Keys) { $nsMgr.AddNamespace($key, $ns[$key]) }

    foreach ($entry in (Select-Xml -Xml $feed -Namespace $ns -XPath '//a:entry').Node) {
        $props = $entry.SelectSingleNode('m:properties', $nsMgr)
        [PSCustomObject]@{
            Id          = $props.SelectSingleNode('d:Id', $nsMgr).InnerText
            ProjectUrl  = $props.SelectSingleNode('d:ProjectUrl', $nsMgr).InnerText
            Author      = $props.SelectSingleNode('d:Authors', $nsMgr).InnerText
            Tags        = $props.SelectSingleNode('d:Tags', $nsMgr).InnerText
            Created     = [datetime]$props.SelectSingleNode('d:Created', $nsMgr).InnerText
            Published   = [datetime]$props.SelectSingleNode('d:Published', $nsMgr).InnerText
            Downloads   = [long]$props.SelectSingleNode('d:DownloadCount', $nsMgr).InnerText
            Description = $props.SelectSingleNode('d:Description', $nsMgr).InnerText
        }
    }
}

# Modules already on the list, by display name and by Gallery package id where the link points at the Gallery.
$content = Get-Content -Path $Path -Raw
$entryPattern = '(?m)^- \[(?<Name>[^\]]+)\]\((?<Url>[^)]+)\) - .+$'
$knownNames = [System.Collections.Generic.HashSet[string]]::new()
foreach ($entryMatch in [regex]::Matches($content, $entryPattern)) {
    [void]$knownNames.Add((Get-NormalizedName $entryMatch.Groups['Name'].Value))
    if ($entryMatch.Groups['Url'].Value -match 'powershellgallery\.com/packages/(?<Id>[^/?#]+)') {
        [void]$knownNames.Add((Get-NormalizedName $Matches.Id))
    }
}

$fromDate = (Get-Date).ToUniversalTime().AddDays(-$MaxAgeDays)
$toDate = (Get-Date).ToUniversalTime().AddDays(-$MinAgeDays)

# Gallery timestamps are UTC but come back without an offset, so compare them as UTC.
function ConvertTo-Utc {
    param([datetime]$Value)
    [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
}

# Step 1: every module whose latest stable version was published on or after the window start.
$latestById = [ordered]@{}
$skip = 0
$reachedWindowStart = $false
while (-not $reachedWindowStart) {
    $searchUri = "$galleryApi/Search()?searchTerm=''&targetFramework=''&includePrerelease=false" +
        "&`$filter=IsLatestVersion&`$orderby=Published desc&`$skip=$skip&`$top=$pageSize"
    $page = @(Get-GalleryFeedPage -Uri $searchUri)
    if ($page.Count -eq 0) {
        break
    }

    foreach ($entry in $page) {
        if ((ConvertTo-Utc $entry.Published) -lt $fromDate) {
            $reachedWindowStart = $true
            break
        }
        # Search() covers scripts as well as modules; modules carry the PSModule tag.
        if ($entry.Tags -notmatch '(^|\s)PSModule(\s|$)') {
            continue
        }
        if ($knownNames.Contains((Get-NormalizedName $entry.Id))) {
            continue
        }
        if (-not $latestById.Contains($entry.Id)) {
            $latestById[$entry.Id] = $entry
        }
    }

    $skip += $pageSize
}

Write-Verbose "$($latestById.Count) unknown modules published since $($fromDate.ToString('yyyy-MM-dd')); checking first-published dates."

# Step 2: earliest-ever version of each, in parallel. Single page, ascending, top 1.
$earliestById = $latestById.Keys | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $id = $_
    $idLiteral = $id -replace "'", "''"
    $uri = "$($using:galleryApi)/Packages()?`$filter=Id eq '$idLiteral'&`$orderby=Created asc&`$top=1"

    try {
        $response = Invoke-WebRequest -Uri $uri -MaximumRetryCount 3 -RetryIntervalSec 5 -ErrorAction Stop
    }
    catch {
        Write-Warning "Earliest-version lookup failed for ${id}: $($_.Exception.Message)"
        return
    }

    [xml]$feed = $response.Content
    $nsMgr = [System.Xml.XmlNamespaceManager]::new($feed.NameTable)
    $nsMap = $using:ns
    foreach ($key in $nsMap.Keys) { $nsMgr.AddNamespace($key, $nsMap[$key]) }

    $created = $feed.SelectSingleNode('//a:entry/m:properties/d:Created', $nsMgr)
    if ($created) {
        [PSCustomObject]@{
            Id      = $id
            Created = [datetime]::SpecifyKind([datetime]$created.InnerText, [System.DateTimeKind]::Utc)
        }
    }
}

# Step 3: keep only modules whose first-ever version falls inside the window.
$results = foreach ($earliest in $earliestById) {
    if ($earliest.Created -lt $fromDate -or $earliest.Created -gt $toDate) {
        # Not actually new - just another release of a module that already existed before the window,
        # or too new to review yet.
        continue
    }

    $latest = $latestById[$earliest.Id]
    $galleryUrl = "https://www.powershellgallery.com/packages/$($earliest.Id)"
    [PSCustomObject]@{
        Name           = $earliest.Id
        ProjectUrl     = if ($latest.ProjectUrl) { $latest.ProjectUrl } else { $galleryUrl }
        GalleryUrl     = $galleryUrl
        Author         = $latest.Author
        FirstPublished = $earliest.Created
        Published      = $latest.Published
        Downloads      = $latest.Downloads
        Description    = $latest.Description
    }
}

$results | Sort-Object FirstPublished -Descending
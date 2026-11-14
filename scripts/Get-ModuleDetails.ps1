#Requires -Version 7.0
<#
.SYNOPSIS
    Lists every module in README.md along with its name, URL, PowerShell Gallery author, and download count.
.PARAMETER Path
    Path to the README.md file to parse.
.PARAMETER ThrottleLimit
    Maximum number of concurrent PowerShell Gallery lookups.
.EXAMPLE
    ./Get-ModuleDetails.ps1 | Format-Table
.EXAMPLE
    ./Get-ModuleDetails.ps1 | Export-Csv ./modules.csv -NoTypeInformation
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot '..' 'README.md'),
    [int]$ThrottleLimit = 10
)

$content = Get-Content -Path $Path -Raw
$entryPattern = '(?m)^- \[(?<Name>[^\]]+)\]\((?<Url>[^)]+)\) - .+$'
$entryMatches = [regex]::Matches($content, $entryPattern)

$entryMatches | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    function Find-GalleryPackage {
        param([string]$Id)
        $escapedId = $Id -replace "'", "''"
        $filter = "Id eq '$escapedId' and IsLatestVersion eq true"
        $query = "%24filter=$([uri]::EscapeDataString($filter))&%24top=1"
        $uri = "https://www.powershellgallery.com/api/v2/Packages()?$query"
        try {
            Invoke-RestMethod -Uri $uri -Headers @{Accept = 'application/atom+xml' } -ErrorAction Stop
        }
        catch {
            $null
        }
    }

    $name = $_.Groups['Name'].Value
    $url = $_.Groups['Url'].Value

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($url -match 'powershellgallery\.com/packages/(?<Id>[^/?#]+)') {
        $candidates.Add($Matches.Id)
    }
    $candidates.Add($name)
    $candidates.Add(($name -replace '\s', ''))
    $candidates.Add(($name -replace '\s', '.'))

    $found = $null
    foreach ($candidate in $candidates) {
        $found = Find-GalleryPackage -Id $candidate
        if ($found) { break }
    }

    [PSCustomObject]@{
        Name      = $name
        Url       = $url
        Author    = if ($found) { $found.properties.Authors } else { 'Not found' }
        Downloads = if ($found) { [int64]$found.properties.DownloadCount.InnerText } else { 'Not found' }
    }
}

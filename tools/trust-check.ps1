# Windows PowerShell / PowerShell 7 counterpart of tools/trust-check.sh.
# Reads the OpenSSF Scorecard API, deps.dev and OSV. No account, no token, writes nothing.
#
#   pwsh tools/trust-check.ps1 [-Repo OWNER/NAME] [-Package PYPI_NAME] [-Version X.Y.Z] [-RequirePackage]
#
# Exit status: 0 = every source answered, no critical finding; 1 = a source could not be
# checked (not a pass); 2 = a critical finding. See docs/VERIFY.md for what "critical" means.
param(
    [string]$Repo = 'tokenorama/tokenorama',
    [string]$Package = 'tokenorama',
    [string]$Version = '',
    [switch]$RequirePackage
)
$ErrorActionPreference = 'Stop'
if ($Repo -notmatch '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' -or $Package -notmatch '^[A-Za-z0-9._-]+$' -or
    $Version -notmatch '^[A-Za-z0-9._+!-]*$') { Write-Error 'odd characters in arguments'; exit 64 }
$owner, $name = $Repo -split '/'
$critical = New-Object System.Collections.Generic.List[string]
$unverified = New-Object System.Collections.Generic.List[string]

# Returns the parsed body, or $null and a note in $unverified (or $null quietly when $Quiet404).
function Get-Json([string]$Label, [string]$Url, [switch]$Quiet404, $Body) {
    try {
        if ($Body) { return Invoke-RestMethod -Method Post -Uri $Url -ContentType 'application/json' -Body $Body -TimeoutSec 30 }
        return Invoke-RestMethod -Uri $Url -TimeoutSec 30
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($Quiet404 -and $code -eq 404) { return $null }
        $why = if ($code) { "HTTP $code" } else { "no answer ($($_.Exception.Message))" }
        $unverified.Add("${Label}: $why")
        Write-Host "${Label}: $why"
        return $null
    }
}

Write-Host "Repository  github.com/$Repo"
Write-Host "Package     $Package (PyPI)"

Write-Host "`n== OpenSSF Scorecard (api.scorecard.dev) =="
$sc = Get-Json 'Scorecard' "https://api.scorecard.dev/projects/github.com/$owner/$name"
if ($sc) {
    Write-Host "score $($sc.score) / 10   scored $($sc.date)"
    $sc.checks | Sort-Object { if ($_.score -lt 0) { 99 } else { $_.score } }, name |
        ForEach-Object { '{0,5}  {1}' -f $(if ($_.score -lt 0) { 'n/a' } else { $_.score }), $_.name }
    $dw = $sc.checks | Where-Object { $_.name -eq 'Dangerous-Workflow' }
    if ($dw -and $dw.score -ge 0 -and $dw.score -lt 10) { $critical.Add("Scorecard Dangerous-Workflow scored $($dw.score)/10: $($dw.reason)") }
} else { Write-Host '  No published result. The repository may be private, or Scorecard has not run on it yet.' }

Write-Host "`n== deps.dev: project =="
$pj = Get-Json 'deps.dev project' "https://api.deps.dev/v3/projects/github.com%2F$owner%2F$name"
if ($pj) { Write-Host "licence $($pj.license)   open issues $($pj.openIssuesCount)   OSS-Fuzz $(if ($pj.ossFuzz) { 'yes' } else { 'no' })" }

Write-Host "`n== deps.dev: package and OSV =="
$pk = Get-Json 'deps.dev package' "https://api.deps.dev/v3/systems/pypi/packages/$Package" -Quiet404
if (-not $pk) {
    if ($unverified | Where-Object { $_ -like 'deps.dev package:*' }) { }
    else {
        Write-Host "$Package is not published on PyPI (deps.dev has no such package)"
        if ($RequirePackage) { $unverified.Add("$Package is not published on PyPI") } else { Write-Host '  Skipped: pass -RequirePackage to treat this as unverified.' }
    }
} else {
    if (-not $Version) {
        $pick = @($pk.versions | Where-Object { $_.isDefault }) + @($pk.versions | Select-Object -Last 1) | Select-Object -First 1
        $Version = $pick.versionKey.version
    }
    $ver = Get-Json "deps.dev $Package $Version" "https://api.deps.dev/v3/systems/pypi/packages/$Package/versions/$Version"
    if ($ver) {
        Write-Host "$Package $Version  published $($ver.publishedAt)  licences $($ver.licenses -join ',')"
        Write-Host "  build provenance records on deps.dev: $(@($ver.slsaProvenances).Count)   attestations: $(@($ver.attestations).Count)"
        Write-Host "  advisories listed by deps.dev: $(@($ver.advisoryKeys).Count)"
        foreach ($k in $ver.advisoryKeys) {
            $a = Get-Json "advisory $($k.id)" "https://api.deps.dev/v3/advisories/$($k.id)"
            if ($a) {
                Write-Host "    $($k.id)  CVSS3 $($a.cvss3Score)  $($a.title)"
                if ($a.cvss3Score -ge 9.0) { $critical.Add("$Package ${Version}: $($k.id) (CVSS3 $($a.cvss3Score))") }
            }
        }
    }
    $body = @{ package = @{ name = $Package; ecosystem = 'PyPI' }; version = $Version } | ConvertTo-Json -Depth 3 -Compress
    $osv = Get-Json 'OSV' 'https://api.osv.dev/v1/query' -Body $body
    if ($osv) {
        $vulns = @($osv.vulns | Where-Object { $_ })
        Write-Host "  vulnerabilities listed by OSV: $($vulns.Count)"
        foreach ($v in $vulns) {
            $sev = if ($v.database_specific.severity) { $v.database_specific.severity } else { 'unrated' }
            Write-Host "    $($v.id)  severity $sev  $($v.summary)"
            if ("$sev".ToUpper() -eq 'CRITICAL') { $critical.Add("$Package ${Version}: $($v.id) (OSV severity CRITICAL)") }
        }
    }
}

Write-Host "`n== Result =="
$critical | ForEach-Object { Write-Host "CRITICAL  $_" }
$unverified | ForEach-Object { Write-Host "NOT VERIFIED  $_" }
if ($critical.Count) { Write-Host 'exit 2: critical finding'; exit 2 }
if ($unverified.Count) { Write-Host 'exit 1: at least one source could not be checked, so this is not a pass'; exit 1 }
Write-Host 'exit 0: all sources answered; no critical finding. This is not a statement that the code is free of vulnerabilities.'
exit 0

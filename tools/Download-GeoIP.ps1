param(
    [string]$OutputDir = "../Heco_Firewall/Data/GeoIP",
    [string]$LicenseKey = ""
)

$ErrorActionPreference = "Stop"

if (-not $LicenseKey) {
    Write-Host "GeoIP Database Download Helper" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "GeoLite2 databases from MaxMind require a (free) license key." -ForegroundColor Yellow
    Write-Host "1. Register at https://www.maxmind.com/en/geolite2/signup" -ForegroundColor Yellow
    Write-Host "2. Generate a license key at https://www.maxmind.com/en/accounts/current/license" -ForegroundColor Yellow
    Write-Host "3. Re-run: .\Download-GeoIP.ps1 -LicenseKey YOUR_KEY" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Alternatively, download manually:" -ForegroundColor Cyan
    Write-Host "  https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" -ForegroundColor Cyan
    exit 1
}

$databases = @(
    "GeoLite2-City",
    "GeoLite2-ASN"
)

$resolvedDir = Resolve-Path $OutputDir -ErrorAction SilentlyContinue
if (-not $resolvedDir) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $resolvedDir = Resolve-Path $OutputDir
}

foreach ($db in $databases) {
    $url = "https://download.maxmind.com/app/geoip_download?edition_id=$db&license_key=$LicenseKey&suffix=tar.gz"
    $outputFile = Join-Path $resolvedDir "$db.tar.gz"
    
    Write-Host "Downloading $db..." -ForegroundColor Green
    try {
        Invoke-WebRequest -Uri $url -OutFile $outputFile -UseBasicParsing
        Write-Host "  Saved to $outputFile" -ForegroundColor Green
    }
    catch {
        Write-Host "  Failed to download $db : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Done. Extract the .mmdb files from each .tar.gz into $resolvedDir" -ForegroundColor Cyan

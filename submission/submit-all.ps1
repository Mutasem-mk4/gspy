param (
    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " gspy Submission Automation: Parrot OS & Kali Linux " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# Check if glab is authenticated
$glabStatus = glab auth status 2>&1
if ($glabStatus -match "No token found" -or $glabStatus -match "Unauthorized") {
    Write-Host "⚠️  glab is not authenticated." -ForegroundColor Yellow
    Write-Host "Please authenticate glab first to submit to Parrot OS." -ForegroundColor Yellow
    Write-Host "Run: glab auth login" -ForegroundColor Yellow
    Write-Host "Then re-run this script." -ForegroundColor Yellow
    
    if (-not $Force) {
        $ans = Read-Host "Do you want to continue with Kali Linux submission only? (y/N)"
        if ($ans -notmatch "^y") {
            exit
        }
    }
} else {
    Write-Host "✅ glab is authenticated." -ForegroundColor Green
    Write-Host "Submitting proposal to Parrot OS GitLab..." -ForegroundColor Cyan

    $parrotBody = Get-Content -Raw "gspy\submission\parrot-os-issue.md"
    try {
        # Using glab issue create. We use the project 'parrotlinux/project' as per Parrot OS docs
        # Since creating issues directly on official repos can trigger spam, we will dry-run or prompt unless forced.
        Write-Host "The following command will be executed:"
        Write-Host "glab issue create -R parrotlinux/project -t `"New tool request: gspy — eBPF-based Forensic Go Inspector`" -d <parrot-os-issue.md content>"
        
        $submit = Read-Host "Are you sure you want to submit the issue to Parrot OS? (y/N)"
        if ($submit -match "^y") {
            glab issue create -R "parrotlinux/project" -t "New tool request: gspy — eBPF-based Forensic Go Inspector" -d "$parrotBody"
            Write-Host "✅ Parrot OS issue created successfully." -ForegroundColor Green
        } else {
            Write-Host "Skipped Parrot OS submission." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ Failed to create Parrot OS issue: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Preparing Kali Linux Submission " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$kaliBody = Get-Content -Raw "gspy\submission\kali-linux-issue.md"
$kaliBody | Set-Clipboard

Write-Host "✅ The Kali Linux proposal has been copied to your clipboard!" -ForegroundColor Green
Write-Host "Kali uses Mantis (a web-based bug tracker). Opening bugs.kali.org in your browser..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

Start-Process "https://bugs.kali.org/login_page.php"

Write-Host ""
Write-Host "Instructions for Kali Linux:" -ForegroundColor Yellow
Write-Host "1. Log in to https://bugs.kali.org"
Write-Host "2. Click 'Report Issue'"
Write-Host "3. Select Project: 'Kali Linux'"
Write-Host "4. Category: 'New Tool Requests'"
Write-Host "5. Summary: '[NEW TOOL] gspy — Zero-Footprint eBPF Forensic Inspector for Go Binaries'"
Write-Host "6. Paste the clipboard content into the 'Description' field."
Write-Host "7. Submit the issue."
Write-Host ""
Write-Host "All done! Good luck with the submissions! 🚀" -ForegroundColor Green

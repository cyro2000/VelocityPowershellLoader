[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$REPO_BASE = "https://raw.githubusercontent.com/cyro2000/VelocityPowershellLoader/main"
$TMP       = [System.IO.Path]::GetTempPath().TrimEnd('\')

function Show-LoaderBanner {
    Clear-Host
    $lines = @(
        "  ██╗   ██╗███████╗██╗      ██████╗  ██████╗██╗████████╗██╗   ██╗",
        "  ██║   ██║██╔════╝██║     ██╔═══██╗██╔════╝██║╚══██╔══╝╚██╗ ██╔╝",
        "  ██║   ██║█████╗  ██║     ██║   ██║██║     ██║   ██║    ╚████╔╝ ",
        "  ╚██╗ ██╔╝██╔══╝  ██║     ██║   ██║██║     ██║   ██║     ╚██╔╝  ",
        "   ╚████╔╝ ███████╗███████╗╚██████╔╝╚██████╗██║   ██║      ██║   ",
        "    ╚═══╝  ╚══════╝╚══════╝ ╚═════╝  ╚═════╝╚═╝   ╚═╝      ╚═╝   "
    )
    $shades = @("DarkMagenta","DarkMagenta","Magenta","Magenta","White","DarkMagenta")
    Write-Host ""
    for ($i = 0; $i -lt $lines.Count; $i++) {
        Write-Host $lines[$i] -ForegroundColor $shades[$i]
    }
    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkMagenta
    Write-Host ""
}

function Write-Step([string]$msg) {
    Write-Host "  " -NoNewline
    Write-Host "[" -ForegroundColor DarkGray -NoNewline
    Write-Host ">" -ForegroundColor Magenta -NoNewline
    Write-Host "] " -ForegroundColor DarkGray -NoNewline
    Write-Host $msg -ForegroundColor White
}
function Write-Ok([string]$msg) {
    Write-Host "  " -NoNewline
    Write-Host "[" -ForegroundColor DarkGray -NoNewline
    Write-Host "+" -ForegroundColor Green -NoNewline
    Write-Host "] " -ForegroundColor DarkGray -NoNewline
    Write-Host $msg -ForegroundColor Green
}
function Write-Warn([string]$msg) {
    Write-Host "  " -NoNewline
    Write-Host "[" -ForegroundColor DarkGray -NoNewline
    Write-Host "!" -ForegroundColor Yellow -NoNewline
    Write-Host "] " -ForegroundColor DarkGray -NoNewline
    Write-Host $msg -ForegroundColor Yellow
}
function Write-Fail([string]$msg) {
    Write-Host "  " -NoNewline
    Write-Host "[" -ForegroundColor DarkGray -NoNewline
    Write-Host "x" -ForegroundColor Red -NoNewline
    Write-Host "] " -ForegroundColor DarkGray -NoNewline
    Write-Host $msg -ForegroundColor Red
}

function Get-PythonCmd {
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $v = & $cmd --version 2>&1
            if ($v -match "Python 3\.(\d+)") {
                $minor = [int]$Matches[1]
                if ($minor -ge 8) { return $cmd }
            }
        } catch { }
    }
    return $null
}

function Get-NodeCmd {
    try {
        $v = & node --version 2>&1
        if ($v -match "v(\d+)") {
            if ([int]$Matches[1] -ge 16) { return "node" }
        }
    } catch { }
    return $null
}

function Download-File([string]$url, [string]$dest) {
    try {
        if (Test-Path $dest) {
            Remove-Item -Path $dest -Force -ErrorAction SilentlyContinue
        }
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $dest)
        $wc.Dispose()
        return $true
    } catch {
        try {
            Invoke-RestMethod -Uri $url -OutFile $dest -ErrorAction Stop
            return $true
        } catch {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
}

Show-LoaderBanner

Write-Host "  Select mode:" -ForegroundColor White
Write-Host ""
Write-Host "    [1]  Python  (velocity.py  — full featured, recommended)" -ForegroundColor Magenta
Write-Host "    [2]  Node    (velocity.js  — same engine, no Python needed)" -ForegroundColor Magenta
Write-Host "    [3]  PS1     (VelocityScan — PowerShell native scanner)" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Enter choice: " -ForegroundColor DarkGray -NoNewline
$choice = Read-Host
Write-Host ""

switch ($choice.Trim()) {

    "1" {
        Write-Step "Checking Python..."
        $py = Get-PythonCmd
        if (-not $py) {
            Write-Fail "Python 3.8+ not found."
            Write-Warn "Install from https://python.org/downloads — make sure to check 'Add to PATH'"
            Write-Host ""
            Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 1
        }
        Write-Ok "Found: $py"

        Write-Step "Checking optional deps (psutil)..."
        $psutil = & $py -c "import psutil; print('ok')" 2>&1
        if ($psutil -ne "ok") {
            Write-Warn "psutil not installed — process scanning limited"
            Write-Warn "Install with: $py -m pip install psutil"
        } else {
            Write-Ok "psutil found"
        }

        Write-Step "Downloading velocity.py..."
        $dest = Join-Path $TMP "velocity.py"
        $ok   = Download-File "$REPO_BASE/velocity.py" $dest
        if (-not $ok) {
            Write-Fail "Download failed. Check your connection or the repo URL."
            exit 1
        }
        Write-Ok "Downloaded to $dest"
        Write-Host ""

        Write-Step "Launching Velocity (Python)..."
        Write-Host ""
        Start-Process -FilePath $py -ArgumentList "`"$dest`"" -NoNewWindow -Wait
    }

    "2" {
        Write-Step "Checking Node.js..."
        $node = Get-NodeCmd
        if (-not $node) {
            Write-Fail "Node.js 16+ not found."
            Write-Warn "Install from https://nodejs.org"
            Write-Host ""
            Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 1
        }
        Write-Ok "Found: node"

        Write-Step "Downloading velocity.js..."
        $dest = Join-Path $TMP "velocity.js"
        $ok   = Download-File "$REPO_BASE/velocity.js" $dest
        if (-not $ok) {
            Write-Fail "Download failed. Check your connection or the repo URL."
            exit 1
        }
        Write-Ok "Downloaded to $dest"
        Write-Host ""

        Write-Step "Launching Velocity (Node)..."
        Write-Host ""
        Start-Process -FilePath "node" -ArgumentList "`"$dest`"" -NoNewWindow -Wait
    }

    "3" {
        Write-Step "Downloading VelocityScan.ps1..."
        $dest = Join-Path $TMP "VelocityScan.ps1"
        $ok   = Download-File "$REPO_BASE/VelocityScan.ps1" $dest
        if (-not $ok) {
            Write-Fail "Download failed. Check your connection or the repo URL."
            exit 1
        }
        Write-Ok "Downloaded to $dest"
        Write-Host ""

        Write-Step "Launching VelocityScan..."
        Write-Host ""
        & powershell -NoProfile -ExecutionPolicy Bypass -File $dest
    }

    default {
        Write-Fail "Invalid choice. Run again and enter 1, 2, or 3."
        exit 1
    }
}

Write-Host ""
Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkMagenta
Write-Ok "Done. Temp files in: $TMP"
Write-Host ""

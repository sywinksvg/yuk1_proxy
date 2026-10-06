# yuk1_proxy - Windows 一键安装
# 用法: powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$server = Join-Path $root "server"

Write-Host "=== yuk1_proxy 安装 ===" -ForegroundColor Cyan
Write-Host "安装目录: $root"
Write-Host ""

# 1) 检查 Python
Write-Host "[1/4] 检查 Python ..."
$py = $null
foreach ($c in @("python", "python3", "py")) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) {
    Write-Host "  ✗ 未找到 Python。请先安装 Python 3.10+ : https://www.python.org/downloads/" -ForegroundColor Red
    exit 1
}
$ver = & $py --version 2>&1
Write-Host "  ✓ $ver ($py)" -ForegroundColor Green

# 2) 检查 uv
Write-Host "[2/4] 检查 uv ..."
$uv = (Get-Command uv -ErrorAction SilentlyContinue).Source
if (-not $uv) {
    Write-Host "  未找到 uv，尝试用 pip 安装 ..." -ForegroundColor Yellow
    try {
        & $py -m pip install --quiet uv
        $uv = (Get-Command uv -ErrorAction SilentlyContinue).Source
    } catch { }
}
if ($uv) {
    Write-Host "  ✓ uv: $uv" -ForegroundColor Green
} else {
    Write-Host "  ! uv 不可用，将回退用 venv + pip" -ForegroundColor Yellow
}

# 3) 安装依赖
Write-Host "[3/4] 安装依赖 ..."
if ($uv) {
    Push-Location $server
    try { & $uv sync } finally { Pop-Location }
    Write-Host "  ✓ 依赖已装（uv 环境: server\.venv）" -ForegroundColor Green
} else {
    $venv = Join-Path $server ".venv"
    if (-not (Test-Path $venv)) { & $py -m venv $venv }
    $vpy = Join-Path $venv "Scripts\python.exe"
    & $vpy -m pip install --quiet "mcp>=1.9.0,<2" "requests[socks]>=2.31"
    Write-Host "  ✓ 依赖已装（venv: server\.venv）" -ForegroundColor Green
}

# 4) 自检
Write-Host "[4/4] 自检 ..."
Push-Location $server
try {
    if ($uv) { & $uv run python yuk1_proxy.py doctor 2>&1 | Select-Object -First 12 }
    else { & (Join-Path $server ".venv\Scripts\python.exe") yuk1_proxy.py doctor 2>&1 | Select-Object -First 12 }
} finally { Pop-Location }

Write-Host ""
Write-Host "=== 安装完成 ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "下一步：把下面这段加进你的 MCP 客户端配置（路径已按本机填好）：" -ForegroundColor Yellow
Write-Host ""
$uvPath = if ($uv) { $uv } else { Join-Path $server ".venv\Scripts\python.exe" }
$argsList = if ($uv) { "`"run`", `"--directory`", `"$server`", `"python`", `"mcp_yuk1_proxy.py`"" } else { "`"$server\mcp_yuk1_proxy.py`"" }
Write-Host @"
{
  "mcpServers": {
    "yuk1_proxy": {
      "command": "$uvPath",
      "args": [$argsList]
    }
  }
}
"@
Write-Host ""
Write-Host "详细说明见 docs\01-安装配置.md" -ForegroundColor Gray

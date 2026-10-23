# =============================================================================
#  build_clab.ps1 — C 記憶體安全靶場的一鍵編譯與執行
# =============================================================================
#
#  對應研究報告 CH06 S2（工具鏈：compiler + sanitizer + debugger）。
#
#  為什麼需要這支腳本？本次演練踩到兩個環境坑，都在此自動處理：
#    坑 1：ASan 的 runtime DLL（libclang_rt.asan_dynamic-x86_64.dll）
#          需要與 exe 同目錄，且它自己還依賴 libc++.dll / libunwind.dll
#          → 少了會得到 exit code -1073741515（STATUS_DLL_NOT_FOUND），
#            而且完全沒有任何錯誤訊息，極難診斷。
#    坑 2：專案路徑含中文，ld.lld 無法在該路徑寫入輸出檔
#          → 編譯到 ASCII 暫存目錄，再把報告複製回 findings/。
#    坑 3：本檔必須以 UTF-8 BOM 儲存，否則 PowerShell 會用系統編碼
#          （Windows 繁中為 Big5）解讀，中文註解與字串全部亂碼。
#
#  用法：
#      pwsh -File build_clab.ps1              # 編譯並跑全部 5 個案例
#      pwsh -File build_clab.ps1 -Case 3      # 只跑第 3 個案例
# =============================================================================
param(
    [int]$Case = 0
)

# 注意：這裡刻意不能用 "Stop"。
# 被測程式（懸掛 sanitizer 的靶場）會把 ASan/UBSan 報告寫到 stderr，
# 而 PowerShell 在 ErrorActionPreference=Stop 下會把「原生命令的 stderr 輸出」
# 當成終止性錯誤，導致腳本在第一個案例就中斷。
# 這是自動化時很常見的陷阱：sanitizer 的輸出是「預期中的資料」，
# 不是腳本執行失敗。
$ErrorActionPreference = "Continue"

# --- 尋找 MinGW clang（winget 安裝路徑含 hash，需動態搜尋） ------------------
$mingwRoot = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "MartinStorsjo.LLVM-MinGW*" } |
    Select-Object -First 1

if (-not $mingwRoot) {
    Write-Host "[錯誤] 找不到 LLVM-MinGW。請先執行：" -ForegroundColor Red
    Write-Host "  winget install --id MartinStorsjo.LLVM-MinGW.UCRT --silent" -ForegroundColor Yellow
    exit 1
}

$mingwDir = Get-ChildItem $mingwRoot.FullName -Directory | Select-Object -First 1
$mingw = $mingwDir.FullName
$clang = Join-Path $mingw "bin\clang.exe"

if (-not (Test-Path $clang)) {
    Write-Host "[錯誤] 找不到 clang：$clang" -ForegroundColor Red
    exit 1
}

$labRoot = Split-Path -Parent $PSScriptRoot
$src = Join-Path $PSScriptRoot "clab.c"
$reportDir = Join-Path $labRoot "findings"

# --- 坑 2：編譯到 ASCII 路徑（避免中文路徑讓 ld.lld 失敗） -------------------
$build = Join-Path $env:TEMP "clab_build"
New-Item -ItemType Directory -Force -Path $build | Out-Null
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

# --- 坑 1：ASan runtime DLL 必須與 exe 同目錄 -------------------------------
$runtimeDlls = @(
    "libclang_rt.asan_dynamic-x86_64.dll",
    "libc++.dll",
    "libunwind.dll",
    "libwinpthread-1.dll"
)

Write-Host "=== clang 記憶體安全靶場 ===" -ForegroundColor Cyan
Write-Host ("編譯器  : {0}" -f $clang)
Write-Host ("原始碼  : {0}" -f $src)
Write-Host ("建置目錄: {0}" -f $build)
Write-Host ""

# --- 編譯 -------------------------------------------------------------------
# 注意：PowerShell 會把逗號當參數分隔符，"-fsanitize=address,undefined" 必須加引號
$env:PATH = (Join-Path $mingw 'bin') + ";" + $env:PATH
$exePath = Join-Path $build "clab.exe"
$compileArgs = @(
    "-fsanitize=address,undefined",
    "-fno-omit-frame-pointer",
    "-g",
    "-O0",
    "-o", $exePath,
    $src
)

Write-Host "=== 編譯中 ===" -ForegroundColor Cyan
$compileOut = & $clang @compileArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[失敗] 編譯錯誤：" -ForegroundColor Red
    $compileOut | ForEach-Object { Write-Host ("  {0}" -f $_) }
    exit 1
}
$exeSize = (Get-Item $exePath).Length
Write-Host ("[成功] {0} ({1} bytes)" -f $exePath, $exeSize)
Write-Host ""

# --- 部署 runtime DLL ------------------------------------------------------
foreach ($dll in $runtimeDlls) {
    $p = Join-Path $mingw "bin\$dll"
    if (Test-Path $p) {
        Copy-Item $p $build -Force
    } else {
        Write-Host ("[注意] 找不到 runtime: {0}" -f $dll) -ForegroundColor Yellow
    }
}

# --- 執行 -------------------------------------------------------------------
$env:ASAN_OPTIONS = "detect_leaks=0"   # Windows 下 leak 偵測常有誤報，關閉

$cases = @(
    @{ n = 1; title = "堆疊緩衝區溢位（off-by-one）";        cwe = "CWE-193 / CWE-121" },
    @{ n = 2; title = "整數截斷導致堆積溢位";                 cwe = "CWE-190 -> CWE-122" },
    @{ n = 3; title = "釋放後使用（use-after-free）";         cwe = "CWE-416" },
    @{ n = 4; title = "未初始化讀取";                        cwe = "CWE-457" },
    @{ n = 5; title = "負索引寫入（Big Sleep SQLite 機制）";   cwe = "CWE-787" }
)

$runList = if ($Case -gt 0) { $cases | Where-Object { $_.n -eq $Case } } else { $cases }

$summaryLines = @()
foreach ($c in $runList) {
    $sep = "=" * 78
    Write-Host $sep -ForegroundColor DarkGray
    Write-Host (" CASE {0}：{1}  [{2}]" -f $c.n, $c.title, $c.cwe) -ForegroundColor Cyan
    Write-Host $sep -ForegroundColor DarkGray

    $out = & $exePath $c.n 2>&1
    $code = $LASTEXITCODE

    foreach ($line in $out) {
        $s = "$line"
        if ($s -match "ERROR: AddressSanitizer|runtime error:") {
            Write-Host ("  {0}" -f $s) -ForegroundColor Yellow
        } elseif ($s -match "SUMMARY:") {
            Write-Host ("  {0}" -f $s) -ForegroundColor Red
        } elseif ($s -match "^\[case") {
            Write-Host ("  {0}" -f $s) -ForegroundColor Gray
        }
    }

    # 收集摘要：ASan 與 UBSan 可能「同時」報告同一個案例
    # （UBSan 先攔到索引越界，ASan 隨後攔到實際的記憶體存取）
    $sums = $out | Select-String "SUMMARY:" | ForEach-Object { $_.Line }
    $tags = @()
    foreach ($s in $sums) {
        if ($s -match "AddressSanitizer: (\S+)") {
            $tags += "ASan:" + $Matches[1]
        } elseif ($s -match "UndefinedBehaviorSanitizer") {
            $tags += "UBSan"
        }
    }
    $sanitizer = if ($tags.Count -gt 0) { ($tags | Select-Object -Unique) -join " + " } else { "（無報告）" }
    $summaryLines += [PSCustomObject]@{
        Case      = $c.n
        Name      = $c.title
        CWE       = $c.cwe
        Sanitizer = $sanitizer
        ExitCode  = $code
    }

    $reportFile = Join-Path $reportDir ("clab_case{0}_report.txt" -f $c.n)
    @(
        ("clab.exe case {0} - {1}  [{2}]" -f $c.n, $c.title, $c.cwe),
        ("exit code: {0}" -f $code),
        ("=" * 78),
        ($out -join "`n")
    ) | Out-File $reportFile -Encoding UTF8
    Write-Host ("  -> 完整報告: findings\clab_case{0}_report.txt" -f $c.n) -ForegroundColor DarkGray
    Write-Host ""
}

# --- 總結 -------------------------------------------------------------------
Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host " 總結" -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor Cyan
$summaryLines | Format-Table -AutoSize | Out-String | Write-Host

$detected = ($summaryLines | Where-Object { $_.Sanitizer -ne "（無報告）" }).Count
Write-Host ("  sanitizer 偵測到 {0}/{1} 個案例" -f $detected, $summaryLines.Count) -ForegroundColor Green
Write-Host ""
Write-Host " 對照報告 CH06 S2：這正是「測試與 fuzzing 需要 sanitizer 才有意義」的原因——"
Write-Host " 沒有 sanitizer，案例 1、4、5 都不會產生任何可見錯誤（靜默的記憶體損毀）。"
Write-Host ""

# --- 匯出總結 CSV -----------------------------------------------------------
$csv = Join-Path $reportDir "clab_summary.csv"
$summaryLines | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
Write-Host (" 總結表: findings\clab_summary.csv") -ForegroundColor DarkGray

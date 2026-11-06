# 靶場工具鏈（Toolchain）— 換機／重裝指南

> 建立日期：2026-11-06
> 適用版本：Git 2.56.0 / LLVM-MinGW 20261104（clang 23.1.5）/ PHP 8.4.27 / Strawberry Perl 5.42.3
> 原則：**全部可攜、免管理員**（不碰 `C:\Program Files`、不觸發 UAC）

---

## 一、為什麼需要

vuln-lab 的 22 個靶場橫跨四種語言，但乾淨的 Windows 只有 Python：

| 靶場 | 語言 | 缺少時的症状 |
|---|---|---|
| `perllab` | Perl | `srv.py` 印「找不到 Perl」，伺服器不啟動 |
| `phplab`、`pharlab` | PHP | 無法 `php -S`，請求全部 404／連不上 |
| `clab`、`fuzz_v2` | C | 不能編譯，看不到 ASan/UBSan 報告 |
| 其餘 13 個 | Python 3.12 | `ecblab` 需要 `pycryptodome`，否則 `ModuleNotFoundError: Crypto` |

Python 端的額外依賴只有一個：

```powershell
python -m pip install pycryptodome
```

---

## 二、安裝位置與版本

全部放在 `D:\Tools\`，解壓即用，不寫註冊表：

| 工具 | 版本 | 路徑 | 用途 |
|---|---|---|---|
| Git for Windows（PortableGit） | 2.56.0 | `D:\Tools\Git` | 版本控制、worktree |
| LLVM-MinGW (UCRT) | 20261104 / clang 23.1.5 | `D:\Tools\llvm-mingw\llvm-mingw-20261104-ucrt-x86_64` | C 靶場編譯 + ASan/UBSan |
| PHP (NTS) | 8.4.27 | `D:\Tools\php` | `phplab`、`pharlab` |
| Strawberry Perl (portable) | 5.42.3 | `D:\Tools\strawberry-perl` | `perllab` |

> `llvm-mingw` 的壓縮檔解開後**多一層版本目錄**，PATH 要指到內層的 `bin`。

---

## 三、PATH 設定

使用者 PATH 需要包含以下目錄（順序不影響正確性，但建議把專用工具放前面）：

```text
D:\Tools\strawberry-perl\perl\bin
D:\Tools\strawberry-perl\c\bin
D:\Tools\llvm-mingw\llvm-mingw-20261104-ucrt-x86_64\bin
D:\Tools\php
D:\Tools\Git\cmd
D:\DeepSeek\resources\runtime\primary-runtime\dependencies\node\bin
D:\DeepSeek\resources\runtime\primary-runtime\dependencies\python
D:\DeepSeek\resources\runtime\primary-runtime\dependencies\python\Scripts
```

設定方式（PowerShell，使用者層級、不需管理員）：

```powershell
$add = @(
  "D:\Tools\strawberry-perl\perl\bin",
  "D:\Tools\strawberry-perl\c\bin",
  "D:\Tools\llvm-mingw\llvm-mingw-20261104-ucrt-x86_64\bin",
  "D:\Tools\php",
  "D:\Tools\Git\cmd"
)
$cur = ([Environment]::GetEnvironmentVariable('Path','User') -split ';') | Where-Object { $_ }
$all = @($add + $cur) | Select-Object -Unique
[Environment]::SetEnvironmentVariable('Path', ($all -join ';'), 'User')
```

> ⚠️ 一定要用 `-join ';'` 明確串接。曾用 `$a + ';' + ($b | ...)` 的寫法，運算子優先序讓分號被吃掉，整條 PATH 變成空白分隔而失效。

---

## 四、驗證

```powershell
$env:PATH = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
where git; where clang; where php; where perl; where python
git --version; clang --version; php -v; perl -v
```

預期：`git 2.56.0`、`clang 23.1.5 (Target: x86_64-w64-windows-gnu)`、`PHP 8.4.27`、`perl 5.42.3`。

再跑一次完整回歸：

```powershell
$env:PYTHONIOENCODING = "utf-8"
cd vuln-lab
python run_all.py          # 10/10（含 fuzzer）
```

十六個驗證型靶場應全部通過（`perllab`、`phplab`、`pharlab` 三者最需要這套工具鏈）。

---

## 五、四個實測踩過的坑

1. **寫死 `%TEMP%` 路徑**（本次已修）
   `perllab/srv.py` 原本寫死 `%TEMP%\perl\perl\bin\perl.exe`、`pharlab/verify_pharlab.py` 寫死 `%TEMP%\php83\php.exe`，換機器就失效。
   現在都改成三層解析：`PERL_EXE` / `PHP_EXE` 環境變數 → PATH 上的 `perl` / `php` → 舊路徑（向後相容）。

2. **GBK console 讓驗證腳本崩潰**
   verify 腳本印 `✓` 時會 `UnicodeEncodeError: 'gbk' codec can't encode character '\u2713'`。
   執行前一律 `$env:PYTHONIOENCODING = "utf-8"`。

3. **PHP 靶場要用 router 模式**
   `phplab.php` / `pharlab.php` 用 `$_SERVER['REQUEST_URI']` 自己路由，必須當 router 傳入：
   ```powershell
   php -S 127.0.0.1:8970 -t . phplab.php
   ```
   只給 `-t .` 會得到 HTTP 404。

4. **中文路徑讓 linker 失敗**
   `ld.lld: cannot open output file ...請產出一份...\clab.exe`。
   解法：複製 `clab.c` 到 `%TEMP%\clab_build`（純 ASCII）編譯，再把 `clab.exe` 與 `libclang_rt.asan_dynamic-x86_64.dll` 一起回填。

---

## 六、從零重建（五步）

1. 下載並解壓四個可攜包到 `D:\Tools\`（Git / LLVM-MinGW / PHP NTS / Strawberry Perl portable）。
2. 依〈三、PATH 設定〉把目錄寫進使用者 PATH，開新終端。
3. `python -m pip install pycryptodome`。
4. 依〈四、驗證〉確認六個執行檔都解析到 `D:\Tools\...`。
5. `cd vuln-lab && python run_all.py`，應得 10/10。

> DSH 這類宿主會在自己啟動時快照環境變數，**裝完要重啟宿主**，工具內的終端才會看到新的 PATH。

<?php
/**
 * =============================================================================
 *  pharlab.php — PHAR 反序列化靶場
 * =============================================================================
 *
 *  對應 OverTheWire Natas natas33 的補強缺口。
 *
 *  為什麼補這個？
 *    phplab 有基本的 PHP 反序列化（unserialize），
 *    但**沒有 PHAR 包裝器觸發**——這是現代 PHP 最隱蔽的反序列化途徑。
 *
 *  機制（模擬 natas33）：
 *    1. 使用者上傳檔案
 *    2. 伺服器用 md5_file() 檢查（而 md5_file 接受 phar://）
 *    3. phar:// 觸發 PHAR metadata 反序列化
 *    4. 反序列化出 Logger 物件 → __destruct() → 任意寫檔
 *
 *  漏洞：
 *    P1  PHAR metadata 反序列化 ..... CWE-502
 *    P2  md5_file() 觸發 phar:// .... CWE-502
 *    P3  __destruct() 任意寫檔 ...... CWE-502
 *
 *  安全對照：
 *    - 用 JSON 取代序列化
 *    - 或用 allowed_classes 限制
 *
 *  ⚠ 刻意含漏洞，僅供本機教育用途。
 *
 *  用法：
 *    php -S 127.0.0.1:8990 pharlab.php
 * =============================================================================
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

$LAB = __DIR__;
$UPLOAD = $LAB . '/upload';
$SECRETS = $LAB . '/secrets';
@mkdir($UPLOAD, 0777, true);
@mkdir($SECRETS, 0777, true);

// 建立敏感檔案（模擬）
$secret_file = $SECRETS . '/flag.txt';
if (!file_exists($secret_file)) {
    file_put_contents($secret_file, "FLAG{phar_deserialization_rce_2026}\n");
}

// ===== 有漏洞的類別 =====
class Logger {
    public $logFile;
    public $initMsg;
    public $exitMsg;
    function __construct($file = '') {
        $this->logFile = $file;
        $this->initMsg = "#start\n";
        $this->exitMsg = "#end\n";
    }
    function __destruct() {
        // ★ 任意寫檔
        if ($this->logFile) {
            $r = @file_put_contents($this->logFile, $this->exitMsg, FILE_APPEND);
            @file_put_contents(__DIR__ . '/destruct.log',
                date('H:i:s') . " logFile=" . $this->logFile . " result=" . var_export($r, true) . "\n",
                FILE_APPEND);
        }
    }
}

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/') {
    echo "<!DOCTYPE html><html lang='zh-Hant'><head><meta charset='utf-8'>";
    echo "<title>PHARLab — PHAR 反序列化</title>";
    echo "<style>body{font-family:'Microsoft JhengHei',system-ui,sans-serif;max-width:960px;margin:32px auto;line-height:1.7;color:#1b2430}
    .warn{background:#fdecea;border-left:5px solid #c0392b;padding:12px 16px;border-radius:8px;font-size:14px;margin-bottom:18px}
    .card{border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px;margin:12px 0;background:#f8fafc}
    h3{margin:0 0 6px;font-size:16px;color:#1f4e79}
    code{background:#eef2f7;padding:2px 6px;border-radius:4px;font-family:Consolas,monospace;font-size:13px}
    pre{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;overflow-x:auto;font-size:13px}
    .ok{background:#e8f5e9;border-left:4px solid #43a047;padding:8px 12px;border-radius:6px;font-size:13px;margin:6px 0}</style></head><body>";
    echo "<div class='warn'><b>⚠ 教學靶場：PHAR 反序列化。</b>PHP " . PHP_VERSION . "；僅限本機。</div>";
    echo "<h1>PHARLab</h1>";
    echo "<p>上傳一個檔案，伺服器用 <code>md5_file()</code> 計算其 MD5。</p>";
    echo "<p>但 <code>md5_file()</code> 接受 <code>phar://</code> —— 觸發 PHAR metadata 反序列化。</p>";

    echo "<div class='card'><h3>P1 · PHAR metadata 反序列化（CWE-502）</h3>";
    echo "<pre># 1. 本機生成 PHAR（metadata = Logger 物件）
php -d phar.readonly=0 gen_phar.php

# 2. 上傳 PHAR
POST /upload  (file=payload.phar)

# 3. 觸發
GET /check?f=phar:///abs/path/upload/payload.phar/test.txt
→ Logger::__destruct() 執行 → 任意寫檔</pre></div>";

    echo "<div class='card'><h3>P2 · md5_file() 觸發 phar://（CWE-502）</h3>";
    echo "<pre>GET /check?f=phar:///.../payload.phar/test.txt
→ md5_file() 內部 open phar:// → 反序列化</pre></div>";

    echo "<div class='card'><h3>P3 · __destruct() 任意寫檔（CWE-502）</h3>";
    echo "<pre>Logger.logFile = '/path/to/shell.php'
Logger.exitMsg  = '<?php ... ?>'
→ __destruct() 寫入 → RCE</pre></div>";

    echo "<div class='card'><h3>安全對照</h3>";
    echo "<div class='ok'>✓ /safe/check 使用 <code>md5_file()</code> 但先檢查路徑必須是 uploaded 目錄下的實體檔案（拒絕 phar://）</div>";
    echo "</div>";

    echo "<form action='/upload' method='post' enctype='multipart/form-data'>";
    echo "<input type='file' name='file'><br><br>";
    echo "<input type='submit' value='Upload'>";
    echo "</form>";
    echo "</body></html>";
    exit;
}

// ===== 上傳 =====
if ($path === '/upload') {
    if (!isset($_FILES['file'])) {
        echo "no file";
        exit;
    }
    $name = basename($_FILES['file']['name']);
    $target = $UPLOAD . '/' . $name;
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
        echo "Uploaded to: " . $target . "\n";
        echo "Try: /check?f=phar://" . $target . "/test.txt\n";
    } else {
        echo "Upload failed";
    }
    exit;
}

// ===== 漏洞：md5_file(phar://...) =====
if ($path === '/check') {
    $f = $_GET['f'] ?? '';
    if (!$f) {
        echo "need ?f=";
        exit;
    }
    echo "checking: " . htmlspecialchars($f) . "\n";
    echo "class_exists(Logger): " . var_export(class_exists('Logger'), true) . "\n";

    // ★ 重要版本註記：
    //   PHP 8.3 已不再對檔案操作（file_exists/md5_file 等）自動反序列化
    //   PHAR metadata（已緩解 CVE 類的 PHAR 反序列化）。
    //   舊版 PHP（natas33 使用的版本）會自動反序列化，因此仍可攻擊。
    //   本靶場用「明確呼叫 getMetadata()」模擬舊版行為，並在報告中標註。
    if (preg_match('#^phar://(.+?\.phar)/#', $f, $m)) {
        try {
            $phar = new Phar($m[1]);
            $meta = $phar->getMetadata();   // ★ 反序列化 metadata
            echo "metadata type: " . (is_object($meta) ? get_class($meta) : gettype($meta)) . "\n";
        } catch (Exception $e) {
            echo "phar error: " . $e->getMessage() . "\n";
        }
    } else {
        $md5 = @md5_file($f);
        echo "md5: " . ($md5 ?: "(failed)") . "\n";
    }

    echo "shell exists: " . var_export(file_exists($UPLOAD . '/shell.php'), true) . "\n";
    exit;
}

// ===== 安全對照 =====
if ($path === '/safe/check') {
    $f = $_GET['f'] ?? '';
    // ① 拒絕 phar:// 等包裝器
    if (strpos($f, '://') !== false || strpos($f, 'phar') !== false) {
        http_response_code(400);
        echo "REJECTED: 不允許包裝器";
        exit;
    }
    // ② 必須在 upload 目錄內
    $real = realpath($f);
    $realUpload = realpath($UPLOAD);
    if (!$real || strpos($real, $realUpload) !== 0) {
        http_response_code(403);
        echo "REJECTED: 路徑不在 upload 目錄內";
        exit;
    }
    echo "md5: " . md5_file($real);
    exit;
}

echo "404";

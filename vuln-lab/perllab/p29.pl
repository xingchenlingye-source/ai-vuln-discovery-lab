#!/usr/bin/perl
# =============================================================================
#  p29.pl — Perl open() 命令注入（對應 natas29）
# =============================================================================
#
#  源碼（模擬 natas29）：
#    if($f =~ /secret/){ print "blocked"; }
#    else { open(FD, "$f.txt"); ... }
#
#  漏洞：
#    · open(FD, "$f.txt") 是 2 參數形式 → '$f' 以 '|' 開頭可執行命令
#    · 但會加上 .txt → 用 %00 截斷
#    · filter 擋 'secret' → 用 'se''cret'（shell 空字串連接）繞過
#
#  用法：
#    GET /p29?file=perl+underground     （正常）
#    GET /p29?file=|echo+hello%00       （命令執行）
#    GET /p29?file=|cat+secret.txt%00   （被擋）
#    GET /p29?file=|cat+se''cret.txt%00 （繞過）
# =============================================================================

use strict;
use warnings;
use CGI qw(:standard);

print "Content-Type: text/html; charset=utf-8\n\n";

my $LAB = $0;
$LAB =~ s{[^/\\]+$}{};
my $secret_file = $LAB . "secrets/secret.txt";

my $f = param('file');
$f = '' unless defined $f;

print "<h2>P29 · Perl open() 命令注入</h2>\n";
print "<p>輸入: <code>" . escapeHTML($f) . "</code></p>\n";

# ★ 過濾（模擬 natas29）
if ($f =~ /secret/) {
    print "<p style='color:red'>★ 被過濾：含 'secret'</p>\n";
    print "<p>試著用 <code>se''cret</code>（shell 空字串連接）繞過</p>\n";
    exit 0;
}

# ★ 漏洞：2 參數 open + .txt 後綴
my $path = "$f.txt";
print "<p>open(FD, <code>" . escapeHTML($path) . "</code>)</p>\n";

if (open(my $fd, $path)) {
    print "<pre>";
    my $n = 0;
    while (my $line = <$fd>) {
        print escapeHTML($line);
        last if ++$n > 50;
    }
    print "</pre>";
    close($fd);
} else {
    print "<p style='color:red'>open 失敗: " . escapeHTML($!) . "</p>\n";
}

print "<hr><p>提示：</p>\n";
print "<div class='pl'>|echo+hello%00 → 執行 echo（%00 截斷 .txt）</div>\n";
print "<div class='pl'>|cat+se''cret.txt%00 → 繞過過濾讀取 secrets/secret.txt</div>\n";

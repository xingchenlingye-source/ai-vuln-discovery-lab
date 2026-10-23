#!/usr/bin/perl
# =============================================================================
#  p31.pl — CGI param() + ARGV 技巧（對應 natas31）
# =============================================================================
#
#  源碼（模擬 natas31）：
#    my $cgi = CGI->new;
#    if ($cgi->upload('file')) {          # 只要求其中一個 file 是檔案
#        my $file = $cgi->param('file');  # 標量上下文 → 取第一個值
#        while (<$file>) { ... }          # "<>" 對字串 "ARGV" 遍歷 @ARGV
#    }
#
#  漏洞機制（三層誤解）：
#    ① upload('file') 只要求「其中一個」file 是檔案
#    ② param('file') 有多值時返回列表，標量取「第一個」
#    ③ <> 對字串 "ARGV" 會遍歷 @ARGV（URL ? 後的參數）當檔案路徑
#
#  用法：
#    POST /p31?/etc/passwd   (multipart: file=ARGV + 一個真檔案)
# =============================================================================

use strict;
use warnings;
use CGI;

print "Content-Type: text/html; charset=utf-8\n\n";

my $cgi = CGI->new;

print "<h2>P31 · CGI param() + ARGV</h2>\n";
print "<p>@ARGV = <code>" . join(" | ", @ARGV) . "</code></p>\n";

if ($cgi->upload('file')) {
    # ★ 標量上下文 → 取第一個值
    my $file = $cgi->param('file');
    print "<p>param('file') 標量 = <code>" . CGI::escapeHTML(
        ref($file) ? "(filehandle)" : $file) . "</code></p>\n";
    print "<p>param('file') 值個數 = " . (scalar $cgi->param('file')) . "</p>\n";

    print "<pre>";
    my $n = 0;
    # ★ 漏洞：<> 對字串 "ARGV" 會遍歷 @ARGV
    while (<$file>) {
        print CGI::escapeHTML($_);
        last if ++$n > 100;
    }
    print "</pre>";
} else {
    print "<p>需要上傳檔案（multipart 的 file 參數）</p>\n";
}

print "<hr><p>提示：</p>\n";
print "<div class='pl'>POST /p31?/etc/passwd  (multipart: file=ARGV + file=\@dummy)</div>\n";
print "<p>① upload('file') 只要有<b>一個</b>真檔案就為真</p>\n";
print "<p>② param('file') 取<b>第一個</b>值（= \"ARGV\"）</p>\n";
print "<p>③ <code>&lt;&gt;</code> 對 \"ARGV\" 遍歷 <code>@ARGV</code>（URL ? 後的參數）</p>\n";

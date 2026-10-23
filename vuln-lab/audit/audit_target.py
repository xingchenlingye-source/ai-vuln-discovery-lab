#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
內部工具服務 — 資料查詢與系統診斷 API

提供給內部維運團隊使用的輕量服務：
  /search    查詢使用者資料
  /hello     招呼訊息
  /file      讀取設定檔
  /ping      網路診斷
  /import    匯入設定資料
  /config    服務設定查詢（唯讀）
  /hash      計算字串雜湊（校驗用）
  /quote     取得每日一語

版本：1.4.2
"""

import hashlib
import json
import logging
import os
import pickle
import sqlite3
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CACHE_DIR = os.path.join(BASE_DIR, "cache")
DB_PATH = os.path.join(DATA_DIR, "service.db")

for d in (DATA_DIR, CACHE_DIR):
    os.makedirs(d, exist_ok=True)

LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger("service")

DAILY_QUOTES = [
    "先讓它能動，再讓它正確，最後讓它快。",
    "過早最佳化是萬惡之源。",
    "簡潔是可靠性的前提。",
    "任何足夠複雜的系統都來自一個簡單的系統。",
]


def bootstrap():
    """初始化服務所需的資料檔與資料表。"""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, username TEXT, role TEXT, secret TEXT)"
    )
    cur.executemany(
        "INSERT OR IGNORE INTO users VALUES (?,?,?,?)",
        [
            (1, "alice", "user", "alice-token-a1"),
            (2, "bob", "user", "bob-token-b2"),
            (3, "admin", "admin", "ADMIN_TOKEN_X9"),
        ],
    )
    con.commit()
    con.close()

    for name, content in (
        ("app.conf", "listen=127.0.0.1\nport=8080\nworkers=4\n"),
        ("version.txt", "service version 1.4.2\n"),
        ("featureflags.json", json.dumps({"beta": False, "verbose": True})),
    ):
        p = os.path.join(DATA_DIR, name)
        if not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)


def compute_hash(value: str, algo: str = "sha256") -> str:
    """以指定演算法計算字串雜湊。"""
    h = hashlib.new(algo)
    h.update(value.encode("utf-8"))
    return h.hexdigest()


def is_valid_name(value: str) -> bool:
    """名稱僅允許英數與底線，長度 1 到 32。"""
    if not value or len(value) > 32:
        return False
    return all(c.isalnum() or c == "_" for c in value)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


HTML = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>內部工具服務 v1.4.2</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:860px;margin:36px auto;
      line-height:1.7;color:#20262e}}
 h1{{font-size:22px}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;font-size:13px}}
 pre{{background:#20262e;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
 .muted{{color:#6b7684;font-size:13px}}
</style></head><body>
<h1>內部工具服務</h1>
<p class="muted">v1.4.2 · {ts}</p>
{content}
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "InternalTools/1.4.2"
    protocol_version = "HTTP/1.1"

    def _respond(self, code, body):
        payload = HTML.format(ts=now_iso(), content=body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def do_GET(self):
        parsed = urlparse(self.path)
        args = parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            body = (
                "<p>可用端點：</p><ul>"
                "<li><code>/search?q=</code></li>"
                "<li><code>/hello?name=</code></li>"
                "<li><code>/file?doc=</code></li>"
                "<li><code>/ping?target=</code></li>"
                "<li><code>/import?payload=</code></li>"
                "<li><code>/config</code></li>"
                "<li><code>/hash?v=&amp;algo=</code></li>"
                "<li><code>/quote?idx=</code></li>"
                "</ul>"
            )
            return self._respond(200, body)

        if path == "/search":
            term = args.get("q", [""])[0]
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            statement = (
                "SELECT id, username, role, secret FROM users "
                "WHERE username = '%s'" % term
            )
            try:
                cur.execute(statement)
                rows = cur.fetchall()
                if rows:
                    rendered = "\n".join(
                        " | ".join(str(c) for c in row) for row in rows
                    )
                    body = "<h2>查詢結果</h2><pre>%s</pre>" % rendered
                else:
                    body = "<h2>查詢結果</h2><p>查無資料。</p>"
            except Exception as exc:
                body = "<h2>查詢失敗</h2><pre>%s</pre>" % exc
            finally:
                con.close()
            return self._respond(200, body)

        if path == "/hello":
            name = args.get("name", ["訪客"])[0]
            body = "<h2>招呼</h2><p>你好，%s！</p>" % name
            return self._respond(200, body)

        if path == "/file":
            doc = args.get("doc", ["version.txt"])[0]
            target = os.path.join(DATA_DIR, doc)
            try:
                with open(target, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                body = "<h2>%s</h2><pre>%s</pre>" % (doc, text)
            except Exception as exc:
                body = "<h2>讀取失敗</h2><pre>%s</pre>" % exc
            return self._respond(200, body)

        if path == "/ping":
            target = args.get("target", ["127.0.0.1"])[0]
            command = "ping -n 1 " + target
            try:
                proc = subprocess.run(
                    command, shell=True, capture_output=True, text=True, timeout=15
                )
                output = proc.stdout or proc.stderr
            except Exception as exc:
                output = "command failed: %s" % exc
            body = "<h2>網路診斷</h2><pre>%s</pre>" % output
            return self._respond(200, body)

        if path == "/import":
            payload = args.get("payload", [""])[0]
            try:
                raw = bytes.fromhex(payload)
                config = pickle.loads(raw)
                body = "<h2>匯入結果</h2><pre>%s</pre>" % config
            except Exception as exc:
                body = "<h2>匯入失敗</h2><pre>%s</pre>" % exc
            return self._respond(200, body)

        if path == "/config":
            safe = {
                "version": "1.4.2",
                "listen": HOST,
                "data_dir": os.path.basename(DATA_DIR),
                "started": now_iso(),
            }
            body = "<h2>服務設定</h2><pre>%s</pre>" % json.dumps(
                safe, indent=2, ensure_ascii=False
            )
            return self._respond(200, body)

        if path == "/hash":
            value = args.get("v", [""])[0]
            algo = args.get("algo", ["sha256"])[0]
            if algo not in ("md5", "sha1", "sha256", "sha512"):
                return self._respond(400, "<h2>不支援的演算法</h2>")
            digest = compute_hash(value, algo)
            body = "<h2>雜湊</h2><pre>%s(%s) = %s</pre>" % (algo, value, digest)
            return self._respond(200, body)

        if path == "/quote":
            try:
                idx = int(args.get("idx", ["0"])[0])
                text = DAILY_QUOTES[idx % len(DAILY_QUOTES)]
                body = "<h2>每日一語</h2><p>%s</p>" % text
            except Exception as exc:
                body = "<h2>參數錯誤</h2><pre>%s</pre>" % exc
            return self._respond(200, body)

        return self._respond(404, "<h2>404</h2><p>找不到路徑。</p>")


def main():
    bootstrap()
    log.info("service starting on %s:%d", HOST, PORT)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("service stopping")
        server.server_close()


if __name__ == "__main__":
    main()

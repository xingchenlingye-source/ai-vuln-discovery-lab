#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 sbom.py — SBOM 生成、雜湊清單與簽章驗證
=============================================================================

 對應研究報告 CH06 S1（OWASP Top 10:2025 **A03 軟體供應鏈失效**）
 與 CH04（工具生態）。

 為什麼需要自己寫？
   本環境沒有 cyclonedx-py / spdx-tools / sigstore。
   但 SBOM 本質是**結構化清單**、簽章本質是 **HMAC** —— 標準庫即可實作。

 本工具提供三種能力（對應 OWASP A03 的可行動項目）：
   1. **generate**  —— 從 requirements.txt 產生 CycloneDX 1.5 JSON 格式的 SBOM
   2. **hash**      —— 為檔案產生 SHA-256 清單（完整性基準）
   3. **sign/verify** —— 以 HMAC-SHA256 對 SBOM 簽章與驗證

 用法：
   python sbom.py generate requirements-vulnerable.txt sbom.json
   python sbom.py hash . hashlist.json
   python sbom.py sign sbom.json sbom.sig
   python sbom.py verify sbom.json sbom.sig

 注意（誠實說明本工具的邊界）：
   - HMAC 是**對稱式**簽章：能防「傳輸中被改」，但無法防「簽章者本身不可信」。
     真正的供應鏈簽章應使用**非對稱簽章**（Sigstore/cosign、GPG），
     讓任何人可用公鑰驗證而無需持有密鑰。
   - 本工具示範「完整性驗證」的機制，不含信任鏈（PKI）的部分。
=============================================================================
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import uuid
from datetime import datetime, timezone

KEY_FILE = ".sbom_key"


# ---------------------------------------------------------------------------
# 1. SBOM 生成（CycloneDX 1.5 JSON 子集）
# ---------------------------------------------------------------------------
def parse_requirements(path):
    deps = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", line)
            if m:
                deps.append({"name": m.group(1), "version": m.group(2)})
    return deps


def to_purl(name, version):
    """Package URL（purl）— SBOM 的標準識別碼。"""
    return "pkg:pypi/%s@%s" % (name.lower().replace("_", "-"), version)


def cmd_generate(req_path, out_path):
    deps = parse_requirements(req_path)
    components = []
    for d in deps:
        components.append({
            "type": "library",
            "name": d["name"],
            "version": d["version"],
            "purl": to_purl(d["name"], d["version"]),
        })

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "vuln-lab", "name": "sbom.py", "version": "1.0"}],
            "component": {
                "type": "application",
                "name": "supplychain-lab",
                "version": "1.0.0",
            },
        },
        "components": components,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, ensure_ascii=False, indent=2)

    print("=" * 74)
    print(" SBOM 生成（CycloneDX 1.5 JSON）")
    print("=" * 74)
    print(" 來源      : %s" % req_path)
    print(" 輸出      : %s" % out_path)
    print(" 元件數量  : %d" % len(components))
    print(" serial    : %s" % sbom["serialNumber"])
    print("-" * 74)
    for c in components:
        print("   %-22s %-12s %s" % (c["name"], c["version"], c["purl"]))
    print("=" * 74)
    print("""
 為什麼 SBOM 是 A03 的基礎？
   OWASP A03 的核心困難是「你不知道自己用了什麼、用了哪個版本」。
   SBOM（Software Bill of Materials）就是把這個問題變成「可查詢的清單」——
   有了它，才能回答「Log4Shell 爆發時，我的系統有沒有受影響？」
""")
    return sbom


# ---------------------------------------------------------------------------
# 2. 雜湊清單（完整性基準）
# ---------------------------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_hash(target_dir, out_path):
    entries = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
        for fn in sorted(files):
            if fn.endswith((".pyc", ".sig", ".key")):
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, target_dir).replace("\\", "/")
            entries.append({"path": rel, "sha256": sha256_file(p),
                            "size": os.path.getsize(p)})

    manifest = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "count": len(entries),
        "files": entries,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print("=" * 74)
    print(" 雜湊清單（SHA-256）")
    print("=" * 74)
    print(" 掃描目錄  : %s" % target_dir)
    print(" 檔案數量  : %d" % len(entries))
    print(" 輸出      : %s" % out_path)
    print("-" * 74)
    for e in entries[:12]:
        print("   %s  %s" % (e["sha256"][:16] + "...", e["path"]))
    if len(entries) > 12:
        print("   ... 另有 %d 個" % (len(entries) - 12))
    print("=" * 74)
    print("""
 用途：這是「完整性基準」。若日後任一檔案被篡改，雜湊就會不符。
      攻擊者若能在你的建置流程中改檔（如 SolarWinds 事件），
      雜湊清單是發現它的基本手段。
""")
    return manifest


# ---------------------------------------------------------------------------
# 3. 簽章與驗證（HMAC-SHA256）
# ---------------------------------------------------------------------------
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(KEY_FILE, 0o600)
    print("（已產生新密鑰 %s，權限 600）" % KEY_FILE)
    return key


def cmd_sign(target_path, sig_path):
    key = load_or_create_key()
    with open(target_path, "rb") as f:
        data = f.read()
    sig = hmac.new(key, data, hashlib.sha256).hexdigest()
    payload = {
        "file": os.path.basename(target_path),
        "algorithm": "HMAC-SHA256",
        "sha256": hashlib.sha256(data).hexdigest(),
        "signature": sig,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print("=" * 74)
    print(" 簽章（HMAC-SHA256）")
    print("=" * 74)
    print(" 檔案      : %s" % target_path)
    print(" SHA-256   : %s" % payload["sha256"])
    print(" 簽章      : %s" % sig)
    print(" 輸出      : %s" % sig_path)
    print("=" * 74)
    return payload


def cmd_verify(target_path, sig_path):
    with open(sig_path, "r", encoding="utf-8") as f:
        sig_data = json.load(f)
    key = load_or_create_key()
    with open(target_path, "rb") as f:
        data = f.read()

    actual_hash = hashlib.sha256(data).hexdigest()
    expected_sig = sig_data.get("signature", "")
    actual_sig = hmac.new(key, data, hashlib.sha256).hexdigest()

    hash_ok = (actual_hash == sig_data.get("sha256"))
    sig_ok = hmac.compare_digest(expected_sig, actual_sig)

    print("=" * 74)
    print(" 簽章驗證")
    print("=" * 74)
    print(" 檔案      : %s" % target_path)
    print(" 雜湊一致  : %s" % ("✓" if hash_ok else "✗"))
    print(" 簽章一致  : %s" % ("✓" if sig_ok else "✗"))
    print("=" * 74)
    if hash_ok and sig_ok:
        print(" ✓ 驗證通過：檔案未被篡改，且簽章有效")
        print("""
 邊界說明（重要）：
   此處通過只代表「檔案與簽章一致」。要真正防供應鏈攻擊，還需要：
     1. 非對稱簽章（Sigstore/cosign、GPG）—— 驗證者無需持有密鑰
     2. 信任鏈（PKI）—— 確認簽章者身分
     3. 時間戳與透明度日誌（如 Rekor）—— 防止事後替換
   HMAC 只能做到「完整性」，做不到「來源可信」。
""")
        return 0
    print(" ✗ 驗證失敗：檔案可能已被篡改，或簽章不符")
    return 1


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "generate":
        cmd_generate(sys.argv[2], sys.argv[3])
    elif cmd == "hash":
        cmd_hash(sys.argv[2], sys.argv[3])
    elif cmd == "sign":
        cmd_sign(sys.argv[2], sys.argv[3])
    elif cmd == "verify":
        sys.exit(cmd_verify(sys.argv[2], sys.argv[3]))
    else:
        print("未知指令：%s" % cmd)
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
build_standalone.py — 產生單一 HTML 檔版本（規則資料以 gzip + base64 內嵌）

用途：離線攜帶、內網環境、或上傳到只接受單一檔案的平台。
輸出：dist/yara-rule-searcher-standalone.html
"""
import base64
import gzip
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def main():
    html = read("index.html")
    css = read("assets/style.css")
    lang = read("assets/yara-lang.js")
    app = read("assets/app.js")
    db_js = read("data/yara-db.js")

    m = re.search(r"window\.YARA_DB\s*=\s*", db_js)
    json_text = db_js[m.end():].rstrip().rstrip(";")
    payload = base64.b64encode(gzip.compress(json_text.encode("utf-8"), 9)).decode("ascii")

    html = html.replace('<link rel="stylesheet" href="assets/style.css">', "<style>\n" + css + "\n</style>")
    inline = ("<script>window.YARA_DB_GZ=\"" + payload + "\";</script>\n"
              "<script>\n" + lang + "\n</script>\n<script>\n" + app + "\n</script>")
    html = html.replace('<script src="assets/yara-lang.js"></script>\n<script src="assets/app.js"></script>', inline)
    assert "assets/app.js" not in html, "替換失敗"

    out_dir = os.path.join(ROOT, "dist")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "yara-rule-searcher-standalone.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"已輸出 {out}（{os.path.getsize(out) / 1e6:.1f} MB）")


if __name__ == "__main__":
    main()

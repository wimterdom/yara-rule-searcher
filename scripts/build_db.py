#!/usr/bin/env python3
"""
build_db.py — 下載 YARA Forge 最新釋出版本，解析規則並產生網站使用的本地資料檔 data/yara-db.js

用法：
    python3 scripts/build_db.py                 # 自動抓取最新 release
    python3 scripts/build_db.py --tag 20260927  # 指定版本
    python3 scripts/build_db.py --local ./raw   # 使用已下載的 .yar（目錄內含 core/extended/full 三個 .yar）

只使用 Python 標準函式庫，無需安裝套件。
"""
import argparse
import io
import json
import os
import re
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone

REPO = "YARAHQ/yara-forge"
PACKAGES = ["core", "extended", "full"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_JS = os.path.join(ROOT, "data", "yara-db.js")
OUT_META = os.path.join(ROOT, "data", "version.json")

MODULES = ["pe", "elf", "math", "hash", "dotnet", "console", "string", "time",
           "magic", "cuckoo", "macho", "dex", "lnk", "vt"]
RULE_START = re.compile(r"^((?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([^{]*?))?\s*(\{)?\s*$")
META_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
QUOTED = re.compile(r'"(?:\\.|[^"\\])*"')
IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
MODULE_USE = re.compile(r"\b(" + "|".join(MODULES) + r")\.[A-Za-z_]")


def log(*a):
    print("[build_db]", *a, file=sys.stderr)


def http_get(url, binary=True):
    req = urllib.request.Request(url, headers={"User-Agent": "yara-rule-searcher-builder"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
        return data if binary else data.decode("utf-8")


def latest_tag():
    # 1) 先用 API（Actions 內有 GITHUB_TOKEN 時不會被限流）
    try:
        info = json.loads(http_get(f"https://api.github.com/repos/{REPO}/releases/latest", binary=False))
        if info.get("tag_name"):
            return info["tag_name"], info.get("published_at", "")
    except Exception as e:  # noqa: BLE001
        log("API 查詢失敗，改用 redirect：", e)
    # 2) 退而求其次：讀取 /releases/latest 的轉址
    req = urllib.request.Request(f"https://github.com/{REPO}/releases/latest",
                                 headers={"User-Agent": "yara-rule-searcher-builder"}, method="HEAD")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.geturl().rstrip("/").split("/")[-1], ""


def fetch_package_text(tag, pkg):
    url = f"https://github.com/{REPO}/releases/download/{tag}/yara-forge-rules-{pkg}.zip"
    log("下載", url)
    blob = http_get(url)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        name = next(n for n in z.namelist() if n.endswith(".yar"))
        return z.read(name).decode("utf-8", errors="replace")


def read_local(folder, pkg):
    for dirpath, _, files in os.walk(folder):
        for f in files:
            if f == f"yara-rules-{pkg}.yar":
                with open(os.path.join(dirpath, f), encoding="utf-8", errors="replace") as fh:
                    return fh.read()
    raise FileNotFoundError(f"找不到 yara-rules-{pkg}.yar 於 {folder}")


def rule_names(text):
    names = set()
    for line in text.splitlines():
        m = RULE_START.match(line)
        if m:
            names.add(m.group(2))
    return names


def parse_package_header(text):
    head = {}
    m = re.search(r"/\*(.*?)\*/", text, re.S)
    if m:
        for line in m.group(1).splitlines():
            line = line.strip().lstrip("*").strip()
            if ":" in line:
                k, v = line.split(":", 1)
                head[k.strip()] = v.strip()
    return head


def unquote(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v


def parse_full(text):
    lines = text.splitlines()
    repos, rules = [], []
    cur_repo = -1
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        # 規則集標頭（每個來源 repo 一段）
        if line.startswith("/*") and i + 1 < n and lines[i + 1].strip() == "* YARA Rule Set":
            j = i + 1
            block = []
            while j < n and lines[j].strip() != "*/":
                block.append(lines[j])
                j += 1
            info = {"name": "", "url": "", "commit": "", "retrieved": "", "license": ""}
            lic_idx = None
            for k, b in enumerate(block):
                s = b.strip().lstrip("*").strip()
                if s.startswith("Repository Name:"):
                    info["name"] = s.split(":", 1)[1].strip()
                elif s.startswith("Repository:"):
                    info["url"] = s.split(":", 1)[1].strip()
                elif s.startswith("Git Commit:"):
                    info["commit"] = s.split(":", 1)[1].strip()
                elif s.startswith("Retrieval Date:"):
                    info["retrieved"] = s.split(":", 1)[1].strip()
                elif s == "LICENSE" and lic_idx is None:
                    lic_idx = k
            if lic_idx is not None:
                lic = "\n".join(x[3:] if x.startswith(" * ") else x for x in block[lic_idx + 1:])
                info["license"] = lic.strip(" *\n")
            repos.append(info)
            cur_repo = len(repos) - 1
            i = j + 1
            continue

        m = RULE_START.match(line)
        if m:
            start = i
            j = i
            seen_condition = False
            while j < n:
                if lines[j].strip() == "condition:":
                    seen_condition = True
                # 行首的 "}" 可能是多行十六進位字串的結尾；必須在 condition: 之後才算規則結束
                if lines[j] == "}" and seen_condition:
                    break
                j += 1
            body = "\n".join(lines[start:j + 1])
            rules.append((m, body, cur_repo))
            i = j + 1
            continue
        i += 1
    return repos, rules


def analyse_rule(m, body):
    mods = (m.group(1) or "").split()
    name = m.group(2)
    tags = (m.group(3) or "").split()
    meta = {}
    section = None
    cond_lines = []
    n_strings = 0
    for raw in body.splitlines()[1:]:
        s = raw.strip()
        if s in ("meta:", "strings:", "condition:"):
            section = s[:-1]
            continue
        if section == "meta":
            mm = META_LINE.match(raw)
            if mm and mm.group(1) not in meta:
                meta[mm.group(1)] = unquote(mm.group(2))
        elif section == "strings":
            if s.startswith("$"):
                n_strings += 1
        elif section == "condition":
            cond_lines.append(raw)
    cond = "\n".join(cond_lines)
    if cond.endswith("}"):
        cond = cond[:-1]
    cond_nq = QUOTED.sub('""', cond)
    used_mods = sorted(set(MODULE_USE.findall(cond_nq)))
    idents = set(IDENT.findall(cond_nq))
    return {
        "name": name, "mods": mods, "tags": tags, "meta": meta,
        "modules": used_mods, "idents": idents, "n_strings": n_strings,
    }


def to_int(v, default=0):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", help="指定 release tag（預設最新）")
    ap.add_argument("--local", help="使用本機已解壓縮的 .yar 目錄")
    ap.add_argument("--force", action="store_true", help="版本未變也重新產生")
    args = ap.parse_args()

    published = ""
    if args.local:
        texts = {p: read_local(args.local, p) for p in PACKAGES}
        tag = parse_package_header(texts["full"]).get("Creation Date", "local").replace("-", "")
    else:
        tag, published = (args.tag, "") if args.tag else latest_tag()
        if not args.force and os.path.exists(OUT_META):
            with open(OUT_META, encoding="utf-8") as fh:
                if json.load(fh).get("release") == tag:
                    log(f"已是最新版本 {tag}，不需更新。（加 --force 可強制重建）")
                    return
        texts = {p: fetch_package_text(tag, p) for p in PACKAGES}

    header = parse_package_header(texts["full"])
    core_names = rule_names(texts["core"])
    ext_names = rule_names(texts["extended"])
    repos, raw_rules = parse_full(texts["full"])
    log(f"解析完成：{len(raw_rules)} 條規則、{len(repos)} 個來源")

    analysed = [analyse_rule(m, body) for m, body, _ in raw_rules]
    index_of = {a["name"]: k for k, a in enumerate(analysed)}

    repo_counts = [0] * len(repos)
    out_rules = []
    for k, ((m, body, ri), a) in enumerate(zip(raw_rules, analysed)):
        name = a["name"]
        tier = 0 if name in core_names else (1 if name in ext_names else 2)
        deps = sorted(index_of[x] for x in a["idents"] if x in index_of and x != name)
        meta = a["meta"]
        if ri >= 0:
            repo_counts[ri] += 1
        out_rules.append([
            name,                                  # 0 name
            tier,                                  # 1 tier: 0 core / 1 extended / 2 full
            ri,                                    # 2 repo index
            to_int(meta.get("score"), 0),          # 3 score
            to_int(meta.get("quality"), 0),        # 4 quality
            meta.get("date", ""),                  # 5 date
            meta.get("modified", ""),              # 6 modified
            meta.get("author", ""),                # 7 author
            meta.get("description", ""),           # 8 description
            " ".join(a["tags"]),                   # 9 tags
            a["modules"],                          # 10 modules
            deps,                                  # 11 dependency rule indexes
            "private" in a["mods"],                # 12 private
            meta.get("reference", ""),             # 13 reference
            meta.get("source_url", ""),            # 14 source_url
            meta.get("license_url", ""),           # 15 license_url
            meta.get("id", ""),                    # 16 id
            a["n_strings"],                        # 17 string count
            body,                                  # 18 full rule text
        ])
    for ri, r in enumerate(repos):
        r["count"] = repo_counts[ri]

    tier_counts = [sum(1 for r in out_rules if r[1] <= t) for t in range(3)]
    db = {
        "schema": 1,
        "release": tag,
        "published": published,
        "built": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "forge_version": header.get("YARA-Forge Version", ""),
        "creation_date": header.get("Creation Date", ""),
        "tier_counts": {"core": tier_counts[0], "extended": tier_counts[1], "full": tier_counts[2]},
        "repos": repos,
        "fields": ["name", "tier", "repo", "score", "quality", "date", "modified", "author",
                   "description", "tags", "modules", "deps", "private", "reference",
                   "source_url", "license_url", "id", "n_strings", "text"],
    }

    os.makedirs(os.path.dirname(OUT_JS), exist_ok=True)
    with open(OUT_JS, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("/* 由 scripts/build_db.py 自動產生，請勿手動修改。資料來源：https://github.com/YARAHQ/yara-forge */\n")
        fh.write("window.YARA_DB = ")
        head = json.dumps(db, ensure_ascii=False)
        fh.write(head[:-1] + ',"rules":[\n')
        for k, r in enumerate(out_rules):
            fh.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")))
            fh.write(",\n" if k < len(out_rules) - 1 else "\n")
        fh.write("]};\n")
    with open(OUT_META, "w", encoding="utf-8") as fh:
        json.dump({"release": tag, "built": db["built"], "rules": len(out_rules),
                   "tier_counts": db["tier_counts"]}, fh, ensure_ascii=False, indent=2)
    log(f"已輸出 {OUT_JS}（{os.path.getsize(OUT_JS)/1e6:.1f} MB）")
    log(f"core={tier_counts[0]} extended={tier_counts[1]} full={tier_counts[2]}")


if __name__ == "__main__":
    main()

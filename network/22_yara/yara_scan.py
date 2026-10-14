#!/usr/bin/env python3
"""22 · YARA 规则与恶意样本扫描器

用法:
    python3 yara_scan.py scan --path artifacts/samples [--rules rules/local.yar]
                              [--whitelist artifacts/whitelist.txt] [--json out.json]
    python3 yara_scan.py perf [--count 10000]

能力: 多规则编译与递归扫描、命中详情（规则 / 严重度 / 命中串与偏移）、
路径白名单降噪、耗时统计。样本自造，只扫本地文件。
"""
import argparse
import json
import shutil
import sys
import time
from pathlib import Path

import yara

DEFAULT_RULES = Path(__file__).parent / "rules" / "local.yar"


def load_rules(path):
    try:
        return yara.compile(filepath=str(path))
    except yara.SyntaxError as e:
        print(f"[!] 规则语法错误：{e}", file=sys.stderr)
        sys.exit(2)
    except yara.Error as e:
        print(f"[!] 规则加载失败：{e}", file=sys.stderr)
        sys.exit(2)


def load_whitelist(path):
    """白名单：一行一个「路径子串」，# 开头为注释；命中的文件直接跳过。"""
    if not path:
        return []
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def iter_files(path):
    p = Path(path)
    if p.is_file():
        return [p]
    return sorted(x for x in p.rglob("*") if x.is_file())


def scan_path(rules, path, whitelist):
    """扫描一个文件或目录；返回（命中列表、扫描数、跳过数、失败数、耗时）。"""
    hits, skipped, scanned, errors = [], 0, 0, 0
    t0 = time.perf_counter()
    for f in iter_files(path):
        if any(w in str(f) for w in whitelist):
            skipped += 1
            continue
        scanned += 1
        try:
            matches = rules.match(str(f))
        except yara.Error as e:
            errors += 1
            print(f"[!] 扫描失败 {f}：{e}", file=sys.stderr)
            continue
        for m in matches:
            hits.append({
                "file": str(f),
                "rule": m.rule,
                "severity": m.meta.get("severity", "-"),
                "description": m.meta.get("description", ""),
                "strings": sorted(
                    ({"id": s.identifier,
                      "offset": s.instances[0].offset,
                      "data": s.instances[0].matched_data[:24].decode("utf-8", "replace")}
                     for s in m.strings if s.instances),
                    key=lambda x: x["id"]),
            })
    return hits, scanned, skipped, errors, time.perf_counter() - t0


def print_hits(hits):
    for h in sorted(hits, key=lambda x: (x["file"], x["rule"])):
        print(f"[命中] {h['rule']}（{h['severity']}）→ {h['file']}")
        for s in h["strings"]:
            print(f"       └ {s['id']} @{s['offset']}: {s['data']!r}")


def cmd_scan(a):
    rules = load_rules(a.rules)
    whitelist = load_whitelist(a.whitelist)
    hits, scanned, skipped, errors, elapsed = scan_path(rules, a.path, whitelist)
    print_hits(hits)
    files_hit = len({h["file"] for h in hits})
    wl_note = f" / 白名单跳过 {skipped}" if skipped else ""
    print(f"[=] 扫描 {scanned} 个文件：命中 {len(hits)} 条（{files_hit} 个文件）{wl_note}"
          f" / 读取失败 {errors}，耗时 {elapsed:.2f}s")
    if a.json:
        Path(a.json).write_text(json.dumps(
            {"scanned": scanned, "skipped": skipped, "errors": errors,
             "hits": sorted(hits, key=lambda x: (x["file"], x["rule"]))},
            ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


def cmd_perf(a):
    root = Path(a.dir)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    for i in range(a.count):
        (root / f"f{i:05d}.txt").write_text(
            f"benign sample line for yara perf test #{i}\n", encoding="utf-8")
    print(f"[perf] 已生成 {a.count} 个测试文件 → {root}/")
    rules = load_rules(a.rules)
    hits, scanned, skipped, errors, elapsed = scan_path(rules, root, [])
    print(f"[perf] 扫描 {scanned} 个文件：命中 {len(hits)} 条，"
          f"耗时 {elapsed:.2f}s（验收线 30s）")
    return 0 if elapsed < 30 else 1


def main():
    ap = argparse.ArgumentParser(description="YARA 扫描器（本地文件）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p0 = sub.add_parser("scan")
    p0.add_argument("--path", required=True, help="文件或目录")
    p0.add_argument("--rules", default=str(DEFAULT_RULES))
    p0.add_argument("--whitelist", default=None)
    p0.add_argument("--json", default=None, help="把结构化结果写入该文件")
    p0.set_defaults(func=cmd_scan)

    p1 = sub.add_parser("perf")
    p1.add_argument("--count", type=int, default=10000)
    p1.add_argument("--dir", default="artifacts/perf")
    p1.add_argument("--rules", default=str(DEFAULT_RULES))
    p1.set_defaults(func=cmd_perf)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

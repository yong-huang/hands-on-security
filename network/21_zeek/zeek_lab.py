#!/usr/bin/env python3
"""21 · Zeek 流量分析 —— beacon 心跳检测 / UA 统计 / DGA 疑似 / 分析报告

用法:
    python3 zeek_lab.py beacon --http F [--jitter 2.0] [--min-hits 5]
    python3 zeek_lab.py ua --http F [--top 5]        # 输出「计数 UA」机器可读行
    python3 zeek_lab.py dga --dns F
    python3 zeek_lab.py report --http F --dns F --out R.md

日志兼容 Zeek 的两副面孔：TSV（#fields 表头，默认输出）与 JSON（JSONL）。
只依赖标准库；所有分析离线进行。
"""
import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

VOWELS = set("aeiou")


def read_zeek(path):
    """读一份 Zeek 日志：自动识别 TSV（#fields 头）与 JSON（每行一对象）。"""
    lines = [l for l in Path(path).read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    if not lines:
        return []
    if lines[0].startswith("{"):
        return [json.loads(l) for l in lines]
    fields, rows = [], []
    for l in lines:
        if l.startswith("#fields"):
            fields = l.split("\t")[1:]
        elif l.startswith("#"):
            continue
        else:
            rows.append(dict(zip(fields, l.split("\t"))))
    return rows


def get(row, key):
    v = row.get(key, "-")
    return None if v in ("-", "", None) else v


def find_beacons(http_rows, min_hits=5, jitter=2.0):
    """按（源IP, 目标域名, 目标IP）聚合，返回心跳嫌疑列表。"""
    groups = defaultdict(list)
    for r in http_rows:
        host, src, dst = get(r, "host"), get(r, "id.orig_h"), get(r, "id.resp_h")
        if host and src and dst:
            groups[(src, host, dst)].append(float(r["ts"]))
    hits = []
    for (src, host, dst), ts in sorted(groups.items()):
        ts.sort()
        if len(ts) < min_hits:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean, sd = statistics.mean(gaps), statistics.stdev(gaps)
        if sd <= jitter:
            hits.append((src, host, dst, len(ts), mean, sd))
    return hits, len(groups)


def ua_counts(http_rows):
    counter = Counter(get(r, "user_agent") for r in http_rows)
    counter.pop(None, None)
    return counter


def dga_suspicious(label):
    """简化启发式：长标签 + 含数字 + 元音稀少。真实 DGA 检测靠模型与情报。"""
    if len(label) < 10 or not any(c.isdigit() for c in label):
        return False
    vowels = sum(1 for c in label.lower() if c in VOWELS)
    return vowels / len(label) < 0.34


def dga_hits(dns_rows):
    seen = []
    for r in dns_rows:
        q = get(r, "query")
        if q and dga_suspicious(q.split(".")[0]) and q not in seen:
            seen.append(q)
    return seen


def window(http_rows, dns_rows):
    ts = [float(r["ts"]) for r in http_rows + dns_rows if get(r, "ts")]
    return min(ts), max(ts)


def cmd_beacon(a):
    rows = read_zeek(a.http)
    hits, n_groups = find_beacons(rows, a.min_hits, a.jitter)
    print(f"[beacon] 候选组 {n_groups} 个（按 源IP + 目标域名 聚合）")
    for src, host, dst, n, mean, sd in hits:
        print(f"[beacon] ⚠️ {host} → {dst}：{n} 次请求，"
              f"平均间隔 {mean:.1f}s，标准差 {sd:.2f}s（来源 {src}）")
    print(f"[beacon] 判定（≥{a.min_hits} 次且标准差 ≤{a.jitter}s）：beacon {len(hits)} 个")
    return 0 if hits else 1


def cmd_ua(a):
    for ua, n in ua_counts(read_zeek(a.http)).most_common(a.top):
        print(f"{n} {ua}")
    return 0


def cmd_dga(a):
    rows = read_zeek(a.dns)
    hits = dga_hits(rows)
    print(f"[dga] DNS 查询 {len(rows)} 条；随机型长标签命中 {len(hits)} 个：")
    for q in hits:
        print(f"  ⚠️ {q}")
    return 0


def fmt_ts(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def cmd_report(a):
    http_rows, dns_rows = read_zeek(a.http), read_zeek(a.dns)
    hits, _ = find_beacons(http_rows)
    uas = ua_counts(http_rows)
    dgas = dga_hits(dns_rows)
    t0, t1 = window(http_rows, dns_rows)
    lines = ["# Zeek 流量分析报告（自动生成）", "",
             f"> 数据窗口：{fmt_ts(t0)} — {fmt_ts(t1)} · "
             f"输入：{Path(a.http).name} / {Path(a.dns).name} · 工具：zeek_lab.py", "",
             "## 1. 结论摘要", ""]
    if hits:
        src, host, dst, n, mean, sd = hits[0]
        lines.append(f"主嫌疑：**{host}**（{src} → {dst}）以 {mean:.1f}s 周期回连，"
                     f"间隔标准差仅 {sd:.2f}s——C2 心跳特征明确；"
                     f"另有 DGA 疑似域名 {len(dgas)} 个。")
    else:
        lines.append("未发现低抖动心跳；DGA 疑似域名见下。")
    lines += ["", "## 2. C2 心跳（beacon）", ""]
    if hits:
        lines += ["| 来源 | 目标域名 | 目标 IP | 次数 | 平均间隔 | 标准差 |",
                  "|:---|:---|:---|:---:|:---:|:---:|"]
        for src, host, dst, n, mean, sd in hits:
            lines.append(f"| {src} | {host} | {dst} | {n} | {mean:.1f}s | {sd:.2f}s |")
    else:
        lines.append("（无）")
    lines += ["", "## 3. User-Agent Top 5", "", "| 次数 | UA |", "|:---:|:---|"]
    for ua, n in uas.most_common(5):
        lines.append(f"| {n} | `{ua}` |")
    lines += ["", "## 4. DGA 疑似域名（长标签 + 含数字 + 元音稀少）", ""]
    lines += [f"- `{q}`" for q in dgas] or ["（无）"]
    lines += ["", "> 建议动作：对主嫌疑主机（10.20.30.40）隔离取证，", 
              "> 对 beacon 域名做 DNS/出站封锁；真实环境再上代理日志交叉验证。"]
    Path(a.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[report] 已生成 {a.out}（beacon {len(hits)} / UA {len(uas)} 种 / DGA {len(dgas)} 个）")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Zeek 日志分析（离线）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p0 = sub.add_parser("beacon")
    p0.add_argument("--http", required=True)
    p0.add_argument("--jitter", type=float, default=2.0, help="间隔标准差阈值（秒）")
    p0.add_argument("--min-hits", type=int, default=5, help="最少请求次数")
    p0.set_defaults(func=cmd_beacon)

    p1 = sub.add_parser("ua")
    p1.add_argument("--http", required=True)
    p1.add_argument("--top", type=int, default=5)
    p1.set_defaults(func=cmd_ua)

    p2 = sub.add_parser("dga")
    p2.add_argument("--dns", required=True)
    p2.set_defaults(func=cmd_dga)

    p3 = sub.add_parser("report")
    p3.add_argument("--http", required=True)
    p3.add_argument("--dns", required=True)
    p3.add_argument("--out", required=True)
    p3.set_defaults(func=cmd_report)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

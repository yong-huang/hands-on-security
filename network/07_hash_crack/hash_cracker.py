#!/usr/bin/env python3
"""07 · 哈希识别与口令破解器

用法:
    python3 hash_cracker.py make-sample artifacts/            # 生成演示目标（读 configs/demo_targets.json）
    python3 hash_cracker.py identify <hash> [更多 hash...]     # 按长度/前缀识别类型
    python3 hash_cracker.py crack artifacts/all-hashes.txt -w artifacts/wordlist.txt [-r] [-t 8]
    python3 hash_cracker.py bench artifacts/bcrypt.txt          # MD5 vs bcrypt 单次成本对比

能力：多算法（MD5/SHA1/SHA256）字典攻击 + 规则变换（大小写/尾数字/符号）、
bcrypt 慢哈希成本实测。只依赖标准库 + bcrypt；只攻击本实验自造的样本。
"""
import argparse
import hashlib
import json
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import bcrypt

CONF = Path(__file__).parent / "configs" / "demo_targets.json"
HASHERS = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}
SUFFIXES = ("1", "2", "3", "123", "1234", "!", "2024")


def identify(h):
    """按长度/前缀识别常见哈希类型；返回 (类型, 额外信息)。"""
    if h.startswith(("$2a$", "$2b$", "$2y$")):
        cost = h.split("$")[2] if len(h.split("$")) > 2 else "?"
        return "bcrypt", f"cost={cost}"
    for name, n in (("md5", 32), ("sha1", 40), ("sha256", 64)):
        if len(h) == n and re.fullmatch(r"[0-9a-fA-F]+", h):
            return name, None
    return "unknown", None


def candidates(words, rules):
    """字典候选流；-r 时追加规则变换（大小写、尾数字、尾符号）。"""
    for w in words:
        yield w
        if not rules:
            continue
        yield w.lower()
        yield w.capitalize()
        yield w.upper()
        for suf in SUFFIXES:
            yield f"{w}{suf}"
            yield f"{w.capitalize()}{suf}"


def cmd_make_sample(args):
    conf = json.loads(CONF.read_text(encoding="utf-8"))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "wordlist.txt").write_text("\n".join(conf["wordlist"]) + "\n", encoding="utf-8")
    md5_lines = [hashlib.md5(p.encode()).hexdigest() for p in conf["md5_plain"]]
    (out / "md5-raw.txt").write_text("\n".join(md5_lines) + "\n", encoding="utf-8")
    bcrypt_hash = bcrypt.hashpw(conf["bcrypt_plain"].encode(),
                                bcrypt.gensalt(rounds=conf["bcrypt_cost"])).decode()
    (out / "bcrypt.txt").write_text(bcrypt_hash + "\n", encoding="utf-8")
    (out / "all-hashes.txt").write_text(
        "\n".join([f"md5:{h}" for h in md5_lines] + [f"bcrypt:{bcrypt_hash}"]) + "\n",
        encoding="utf-8")
    print(f"[=] 样本已生成：{out}/（10 个 MD5 + 1 个 bcrypt(cost={conf['bcrypt_cost']})"
          f"，字典 {len(conf['wordlist'])} 词）")
    return 0


def cmd_identify(args):
    for h in args.hashes:
        kind, extra = identify(h)
        tip = f"（{extra}）" if extra else ""
        print(f"[ID] {kind:<8}{tip}  {h[:48]}{'…' if len(h) > 48 else ''}")
    return 0


def cmd_crack(args):
    words = [w.strip() for w in Path(args.wordlist).read_text(encoding="utf-8").splitlines()
             if w.strip() and not w.startswith("#")]
    targets = []
    for line in Path(args.hashfile).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        algo, h = line.split(":", 1)
        targets.append({"algo": algo, "hash": h, "plain": None})
    fast = [t for t in targets if t["algo"] in HASHERS]
    slow = [t for t in targets if t["algo"] not in HASHERS]
    by_hash = {t["hash"]: t for t in fast}
    algos = {t["algo"] for t in fast}

    cands = list(candidates(words, args.rules))
    print(f"[*] 目标 {len(fast)} 个快哈希 + {len(slow)} 个慢哈希；候选 {len(cands)} 条"
          f"（规则{'开' if args.rules else '关'}）× {len(algos)} 算法，线程 {args.threads}")
    t0 = time.perf_counter()
    lock = threading.Lock()

    def worker(chunk):
        for cand in chunk:
            for algo in algos:
                t = by_hash.get(HASHERS[algo](cand.encode()).hexdigest())
                if t and t["plain"] is None:
                    with lock:
                        t["plain"] = cand
                        print(f"[+] 命中：{algo:<6} {t['hash'][:20]}… → {cand}", flush=True)

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        chunk_size = max(1, len(cands) // args.threads + 1)
        futs = [pool.submit(worker, cands[i:i + chunk_size])
                for i in range(0, len(cands), chunk_size)]
        for _ in as_completed(futs):
            pass

    cracked = sum(1 for t in fast if t["plain"])
    dt = time.perf_counter() - t0
    for t in fast:
        if not t["plain"]:
            print(f"[-] 未破：{t['algo']} {t['hash'][:20]}…")
    for t in slow:
        print(f"[!] {t['algo']} 目标跳过字典攻击（单次验证 >100ms，见 bench）："
              f"{t['hash'][:24]}…")
    print(f"[=] 破解 {cracked}/{len(fast)}（耗时 {dt:.2f}s）")
    return 0                                 # 破解数多少都算正常完成，验收在脚本里断言


def cmd_bench(args):
    h = Path(args.bcrypt_file).read_text(encoding="utf-8").strip().splitlines()[0]
    kind, extra = identify(h)
    if kind != "bcrypt":
        print("[!] 需要 bcrypt 哈希文件", file=sys.stderr)
        return 1
    probe = b"not-the-password"
    t0 = time.perf_counter()
    hashlib.md5(probe).hexdigest()
    dt_md5 = time.perf_counter() - t0
    t0 = time.perf_counter()
    ok = bcrypt.checkpw(probe, h.encode())
    dt_bcrypt = time.perf_counter() - t0
    print(f"[*] MD5 单次计算：{dt_md5 * 1e6:.1f}µs（约 {1 / dt_md5:,.0f} 次/秒）")
    print(f"[*] bcrypt（{extra}）单次验证：{dt_bcrypt * 1000:.1f}ms"
          f"（约 {1 / dt_bcrypt:.1f} 次/秒；探针口令{'正确' if ok else '错误'}也一样耗时）")
    print(f"[=] 成本比 ≈ {dt_bcrypt / dt_md5:,.0f}×；cost 每 +1，耗时翻一倍"
          f"——穷举字典的成本同理翻倍")
    return 0


def main():
    parser = argparse.ArgumentParser(description="哈希识别与口令破解（仅限本实验样本）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("make-sample", help="生成演示目标哈希与字典")
    p1.add_argument("out")
    p1.set_defaults(func=cmd_make_sample)

    p2 = sub.add_parser("identify", help="识别哈希类型")
    p2.add_argument("hashes", nargs="+")
    p2.set_defaults(func=cmd_identify)

    p3 = sub.add_parser("crack", help="字典攻击（-r 开启规则变换）")
    p3.add_argument("hashfile")
    p3.add_argument("-w", "--wordlist", required=True)
    p3.add_argument("-r", "--rules", action="store_true", help="开启大小写/尾数字/符号变换")
    p3.add_argument("-t", "--threads", type=int, default=8)
    p3.set_defaults(func=cmd_crack)

    p4 = sub.add_parser("bench", help="MD5 vs bcrypt 单次成本对比")
    p4.add_argument("bcrypt_file")
    p4.set_defaults(func=cmd_bench)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

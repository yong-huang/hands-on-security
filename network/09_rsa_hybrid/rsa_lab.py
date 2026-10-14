#!/usr/bin/env python3
"""09 · RSA 原理与混合加密

用法:
    python3 rsa_lab.py toy                          # 教材版 RSA：p=61, q=53 经典样例
    python3 rsa_lab.py oaep                         # 真实 RSA-OAEP（随机填充）
    python3 rsa_lab.py envelope make artifacts/     # 造 1MB 样本 + 信封加密
    python3 rsa_lab.py envelope open artifacts/     # 解封 + sha256 比对 + 篡改检测

能力：扩展欧几里得求私钥、模幂加解密、同态性演示、RSA-OAEP、
AES-GCM + RSA 信封加密（大文件混合加密的全流程与两种篡改检测）。
只加密本实验自造数据。
"""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

CONF = Path(__file__).parent / "configs" / "demo_params.json"


def load_conf():
    return json.loads(CONF.read_text(encoding="utf-8"))


def egcd(a, b):
    """扩展欧几里得：返回 (g, x, y) 使 a·x + b·y = g = gcd(a, b)。"""
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("无逆元")
    return x % m


# ============================================================ 教材版
def cmd_toy(_args):
    t = load_conf()["toy"]
    p, q, e, m = t["p"], t["q"], t["e"], t["message"]
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    print(f"[*] 选素数 p={p} q={q} → 模数 n=p·q = {n}")
    print(f"[*] 欧拉函数 φ(n)=(p-1)(q-1) = {phi}")
    print(f"[*] 公钥 (e={e}, n={n})；私钥 d = e⁻¹ mod φ(n) = {d}"
          f"（扩展欧几里得求出）")
    c = pow(m, e, n)
    back = pow(c, d, n)
    print(f"[TOY] 加密：m={m} → c = m^e mod n = {c}")
    print(f"[TOY] 解密：c={c} → m' = c^d mod n = {back}")
    ok = back == m and d == 2753 and c == 2790
    print(f"[TOY] 与教材一致（d=2753、c=2790、m'=65）：{'是' if ok else '否'}")

    # 教材版的两个致命弱点（为什么真实 RSA 必须配填充）
    e2, e3 = pow(2, e, n), pow(3, e, n)
    e6 = pow(6, e, n)
    print(f"[弱点] 确定性：同一条消息永远同一个密文（可被比对猜出）")
    print(f"[弱点] 同态性：E(2)·E(3) mod n = {e2 * e3 % n} = E(6) = {e6}"
          f" —— 攻击者能拼出明文 6 的密文")
    return 0 if ok else 1


# ============================================================ OAEP
def load_or_make_key(path, bits):
    path = Path(path)
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return key


def cmd_oaep(args):
    conf = load_conf()
    key = load_or_make_key(Path(args.out) / "rsa_key.pem", conf["rsa_key_size"])
    pub = key.public_key()
    print(f"[*] RSA-{conf['rsa_key_size']} 密钥就绪（{Path(args.out) / 'rsa_key.pem'}，仅本实验用）")
    msg = b"hands-on-security / 09 / the same message"
    c1 = pub.encrypt(msg, asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    c2 = pub.encrypt(msg, asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    back = key.decrypt(c1, asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    print(f"[OAEP] 解密还原：{'是' if back == msg else '否'}")
    print(f"[OAEP] 同一消息两次加密密文相同：{'是' if c1 == c2 else '否'}"
          f"（随机填充 → 密文每次不同，比对攻击失效）")
    return 0 if back == msg and c1 != c2 else 1


# ============================================================ 信封加密
MAGIC = b"HOSEC09E"                                  # 信封文件头


def envelope_bytes(wrapped_key, nonce, ct):
    import struct
    return MAGIC + struct.pack(">H", len(wrapped_key)) + wrapped_key + nonce + ct


def parse_envelope(data):
    import struct
    assert data[:8] == MAGIC, "不是本实验的信封格式"
    klen = struct.unpack(">H", data[8:10])[0]
    wrapped = data[10:10 + klen]
    nonce = data[10 + klen:10 + klen + 12]
    ct = data[10 + klen + 12:]
    return wrapped, nonce, ct


def cmd_envelope(args):
    conf = load_conf()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    sample = out / "sample.bin"
    envf = out / "envelope.bin"

    if args.action == "make":
        key = load_or_make_key(out / "rsa_key.pem", conf["rsa_key_size"])
        data = os.urandom(conf["sample_bytes"])
        sample.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        print(f"[*] 样本 {len(data)} 字节，sha256={digest[:16]}…")
        aes_key = AESGCM.generate_key(bit_length=256)     # 一次性会话密钥
        nonce = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(nonce, data, None)
        wrapped = key.public_key().encrypt(aes_key, asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))
        envf.write_bytes(envelope_bytes(wrapped, nonce, ct))
        print(f"[ENV] 会话密钥 {len(aes_key)}B：RSA-OAEP 封装到 {len(wrapped)}B"
              f"（公钥完成密钥分发）")
        print(f"[ENV] 数据段 {len(ct)}B：AES-256-GCM 加密（含 16B 标签）")
        print(f"[=] 信封文件 {envf.name}：{envf.stat().st_size} 字节 = 头 + 封装密钥"
              f" + nonce + 密文")
        return 0

    # open：解封 → 校验 → 两种篡改
    data = envf.read_bytes()
    key = load_or_make_key(out / "rsa_key.pem", conf["rsa_key_size"])
    wrapped, nonce, ct = parse_envelope(data)

    aes_key = key.decrypt(wrapped, asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    plain = AESGCM(aes_key).decrypt(nonce, ct, None)
    expect = hashlib.sha256(sample.read_bytes()).hexdigest()
    got = hashlib.sha256(plain).hexdigest()
    print(f"[ENV] 解封+解密完成：{len(plain)} 字节")
    print(f"[ENV] sha256 与原文一致：{'是' if got == expect else '否'}"
          f"（{got[:16]}…）")

    bad_ct = bytearray(ct)
    bad_ct[len(bad_ct) // 2] ^= 0x01
    try:
        AESGCM(aes_key).decrypt(nonce, bytes(bad_ct), None)
        print("[篡改] 数据段改 1 字节：竟然通过（不该发生）")
        return 1
    except InvalidTag:
        print("[篡改] 数据段改 1 字节 → InvalidTag（GCM 标签拦下）")

    bad_wrap = bytearray(wrapped)
    bad_wrap[10] ^= 0x01
    try:
        key.decrypt(bytes(bad_wrap), asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))
        print("[篡改] 封装密钥改 1 字节：竟然通过（不该发生）")
        return 1
    except ValueError:
        print("[篡改] 封装密钥改 1 字节 → OAEP 解封失败（ValueError）")
    print("[=] 两层都被保护：数据段靠 GCM 标签、密钥段靠 OAEP 填充校验")
    return 0


def main():
    parser = argparse.ArgumentParser(description="RSA 原理与混合加密（仅本地教学）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("toy")
    p1.set_defaults(func=cmd_toy)

    p2 = sub.add_parser("oaep")
    p2.add_argument("--out", default="artifacts")
    p2.set_defaults(func=cmd_oaep)

    p3 = sub.add_parser("envelope")
    p3.add_argument("action", choices=["make", "open"])
    p3.add_argument("out", nargs="?", default="artifacts")
    p3.set_defaults(func=cmd_envelope)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

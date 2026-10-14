#!/usr/bin/env python3
"""08 · 对称加密实验室（AES 模式对比）

用法:
    python3 aes_lab.py make-image artifacts/penguin          # 画一只企鹅（png + bmp）
    python3 aes_lab.py modes artifacts/penguin.bmp artifacts/   # ECB vs CBC 加密对照图
    python3 aes_lab.py randomness                                 # IV 随机性：ECB 确定性 vs CBC 不可复现
    python3 aes_lab.py gcm                                        # GCM 认证：篡改密文必被拒

能力：AES-ECB/CBC/GCM 三种模式加解密、PKCS7 填充、IV/nonce 生成、
ECB 块重复弱点量化、GCM 完整性检测。依赖 cryptography 与 Pillow。
只加密本实验自造数据；示例密钥仅限教学。
"""
import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

from PIL import Image, ImageDraw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CONF = Path(__file__).parent / "configs" / "demo_params.json"
BLOCK = 16


def load_conf():
    return json.loads(CONF.read_text(encoding="utf-8"))


def demo_key(conf):
    return bytes.fromhex(conf["demo_key_hex"])          # 仅教学：真实密钥必须随机


def pkcs7_pad(data):
    p = padding.PKCS7(BLOCK * 8).padder()
    return p.update(data) + p.finalize()


def pkcs7_unpad(data):
    u = padding.PKCS7(BLOCK * 8).unpadder()
    return u.update(data) + u.finalize()


def ecb_encrypt(key, data):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(data) + e.finalize()


def cbc_encrypt(key, data, iv):
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def gcm_encrypt(key, data, aad=b""):
    nonce = os.urandom(12)                              # 每消息唯一，勿复用
    e = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    e.authenticate_additional_data(aad) if aad else None
    ct = e.update(data) + e.finalize()
    return nonce, ct, e.tag


def repeated_blocks(data):
    """统计重复的 16 字节块数（重复越多，模式泄漏越多）。"""
    blocks = [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]
    c = Counter(blocks)
    return sum(n - 1 for n in c.values() if n > 1)


def draw_penguin(path, conf):
    size = conf["image"]["size"]
    bg = tuple(conf["image"]["background_rgb"])
    img = Image.new("RGB", (size, size), bg)            # 大面积同色背景
    d = ImageDraw.Draw(img)
    w = h = size
    d.ellipse([w * .28, h * .32, w * .72, h * .92], fill=(24, 26, 34))   # 身体
    d.ellipse([w * .36, h * .50, w * .64, h * .88], fill=(250, 250, 250))  # 肚皮
    d.ellipse([w * .33, h * .12, w * .67, h * .48], fill=(24, 26, 34))   # 头
    d.ellipse([w * .40, h * .24, w * .46, h * .31], fill=(250, 250, 250))  # 眼白
    d.ellipse([w * .54, h * .24, w * .60, h * .31], fill=(250, 250, 250))
    d.ellipse([w * .42, h * .26, w * .45, h * .29], fill=(10, 10, 12))   # 瞳孔
    d.ellipse([w * .56, h * .26, w * .59, h * .29], fill=(10, 10, 12))
    d.polygon([(w * .50, h * .30), (w * .43, h * .38), (w * .57, h * .38)],
              fill=(240, 148, 32))                       # 喙
    d.ellipse([w * .18, h * .50, w * .32, h * .80], fill=(20, 22, 30))   # 左翼
    d.ellipse([w * .68, h * .50, w * .82, h * .80], fill=(20, 22, 30))   # 右翼
    d.ellipse([w * .30, h * .86, w * .45, h * .95], fill=(240, 148, 32))  # 脚
    d.ellipse([w * .55, h * .86, w * .70, h * .95], fill=(240, 148, 32))
    path = Path(path).with_suffix("")                    # 传入基名，同时产出 .png/.bmp
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path.with_suffix(".png"))
    img.save(path.with_suffix(".bmp"))
    return img


def pixels_of(img):
    return img.convert("RGB").tobytes()


def image_from_bytes(data, size):
    data = data[:size * size * 3]
    data = data.ljust(size * size * 3, b"\x00")
    return Image.frombytes("RGB", (size, size), data)


def cmd_make_image(args):
    conf = load_conf()
    draw_penguin(args.out, conf)
    base = Path(args.out).with_suffix("")
    print(f"[=] 企鹅已就位：{base}.png / {base}.bmp"
          f"（{conf['image']['size']}×{conf['image']['size']}，同色区域大，专为 ECB 演示定制）")
    return 0


def cmd_modes(args):
    conf = load_conf()
    key = demo_key(conf)
    img = Image.open(args.bmp)
    size = img.width
    plain = pixels_of(img)
    padded = pkcs7_pad(plain)
    print(f"[*] 明文像素 {len(plain)} 字节 → PKCS7 填充 {len(padded) - len(plain)} 字节"
          f"（{len(padded)} = {BLOCK}×{len(padded) // BLOCK}）")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    ct_ecb = ecb_encrypt(key, padded)
    iv = os.urandom(BLOCK)
    ct_cbc = cbc_encrypt(key, padded, iv)
    image_from_bytes(ct_ecb, size).save(out / "ecb.png")
    image_from_bytes(ct_cbc, size).save(out / "cbc.png")

    rep_plain = repeated_blocks(plain)
    rep_ecb = repeated_blocks(ct_ecb)
    rep_cbc = repeated_blocks(ct_cbc)
    print(f"[ECB] 密文重复块 {rep_ecb}（明文重复块 {rep_plain} 原样泄漏）"
          f"——企鹅轮廓在密文里清晰可辨")
    print(f"[CBC] 密文重复块 {rep_cbc}（链式 + 随机 IV 把相同明文块打散成不同密文）")
    print(f"[=] 对照图：{out / 'ecb.png'}（可辨轮廓）与 {out / 'cbc.png'}（噪声）")
    return 0 if rep_ecb >= 10 and rep_cbc == 0 else 1


def cmd_randomness(_args):
    conf = load_conf()
    key = demo_key(conf)
    plain = pkcs7_pad(b"hands-on-security / 08 / rotate the same plaintext " * 4)
    e1, e2 = ecb_encrypt(key, plain), ecb_encrypt(key, plain)
    c1 = cbc_encrypt(key, plain, os.urandom(BLOCK))
    c2 = cbc_encrypt(key, plain, os.urandom(BLOCK))
    print(f"[ECB] 同明文同密钥两次加密，密文一致：{'是' if e1 == e2 else '否'}"
          f"（确定性 —— 可被比对统计）")
    print(f"[CBC] 同明文同密钥两次加密，密文一致：{'是' if c1 == c2 else '否'}"
          f"（随机 IV —— 每次都是新密文）")
    return 0 if e1 == e2 and c1 != c2 else 1


def cmd_gcm(_args):
    conf = load_conf()
    key = demo_key(conf)
    plain = b"amount=100&to=alice"                      # 一条会被篡改的敏感指令
    nonce, ct, tag = gcm_encrypt(key, plain, aad=b"transfer-v1")
    print(f"[*] GCM：nonce {len(nonce)} 字节、密文 {len(ct)} 字节、认证标签 {len(tag)} 字节")
    d = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    d.authenticate_additional_data(b"transfer-v1")
    got = d.update(ct) + d.finalize()
    print(f"[GCM] 正常解密：通过（明文还原 {len(got)} 字节）")

    tampered = bytearray(ct)
    tampered[0] ^= 0x01                                 # 只改 1 个字节
    try:
        d2 = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        d2.authenticate_additional_data(b"transfer-v1")
        d2.update(bytes(tampered)) + d2.finalize()
        print("[GCM] 篡改后解密：竟然通过（不该发生）")
        return 1
    except InvalidTag:
        print("[GCM] 篡改密文第 1 字节后解密：抛 InvalidTag，拒绝输出明文")
        print("[=] 完整性由认证标签兜底——「保密」与「不被篡改」是两件事")
        return 0


def cmd_identify(_args):
    conf = load_conf()
    key = demo_key(conf)
    print(f"[*] 示例密钥指纹（sha256 前 8）：{hashlib.sha256(key).hexdigest()[:8]}"
          f"（密钥本身只写在 configs/，不随报告外传）")
    return 0


def main():
    parser = argparse.ArgumentParser(description="对称加密实验室：AES 模式对比（仅本地教学）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("make-image")
    p1.add_argument("out", help="输出路径（会同时写出 .png 与 .bmp）")
    p1.set_defaults(func=cmd_make_image)

    p2 = sub.add_parser("modes", help="ECB vs CBC 加密对照图")
    p2.add_argument("bmp")
    p2.add_argument("out")
    p2.set_defaults(func=cmd_modes)

    p3 = sub.add_parser("randomness", help="ECB 确定性 vs CBC 随机 IV")
    p3.set_defaults(func=cmd_randomness)

    p4 = sub.add_parser("gcm", help="GCM 认证与篡改检测")
    p4.set_defaults(func=cmd_gcm)

    p5 = sub.add_parser("keyinfo", help="打印示例密钥指纹")
    p5.set_defaults(func=cmd_identify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

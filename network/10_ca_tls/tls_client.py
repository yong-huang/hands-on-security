#!/usr/bin/env python3
"""10 · TLS 客户端：三种信任配置下的握手结果（教学用）

用法:
    python3 tls_client.py --ca artifacts/ca.crt        # 信任实验 CA → 应成功
    python3 tls_client.py                              # 系统信任库 → 应失败（自签）
    python3 tls_client.py --ca artifacts/wrong-ca.crt  # 错误 CA → 应失败

成功时会打印协议版本、密码套件与对端证书的 CN/SAN——X.509 校验做了什么，
一次握手全交代。
"""
import argparse
import socket
import ssl
import sys


def probe(cafile, port):
    if cafile:
        ctx = ssl.create_default_context(cafile=cafile)   # 只信这一个根
    else:
        ctx = ssl.create_default_context()                # 系统信任库
    try:
        with socket.create_connection(("localhost", port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
                cert = tls.getpeercert()
                subject = dict(x[0] for x in cert["subject"])
                san = cert.get("subjectAltName", [])
                print(f"  ✅ 握手成功：{tls.version()} / {tls.cipher()[0]}")
                print(f"     对端证书 CN={subject.get('commonName')} SAN={san}")
                tls.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                first = tls.recv(120).split(b"\r\n")[0].decode()
                print(f"     响应：{first}")
        return True
    except ssl.SSLCertVerificationError as e:
        why = e.verify_message or str(e)
        print(f"  ❌ 校验失败：{why}")
        return False
    except Exception as e:                                  # noqa: BLE001
        print(f"  ❌ 连接失败：{type(e).__name__}: {e}")
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ca", help="信任的 CA 证书（缺省用系统信任库）")
    ap.add_argument("--port", type=int, default=8443, help="HTTPS 服务端口（默认 8443）")
    args = ap.parse_args()
    label = args.ca or "系统信任库"
    print(f"[CLIENT] 信任源：{label}")
    ok = probe(args.ca, args.port)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

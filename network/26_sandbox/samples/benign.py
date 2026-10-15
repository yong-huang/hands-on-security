#!/usr/bin/env python3
# =============================================================================
# 26 · 良性对照样本——纯计算：不写文件、不联网、不拉子进程
#   事件基准：文 件 = 0、网络 = 0、子进程 = 0（监控器的准入线）
# =============================================================================
import hashlib


def sieve(n):
    flags = bytearray([1]) * (n + 1)
    flags[0:2] = b"\x00\x00"
    for i in range(2, int(n ** 0.5) + 1):
        if flags[i]:
            flags[i * i :: i] = bytearray(len(flags[i * i :: i]))
    return sum(flags)


def main():
    primes = sieve(2_000_000)
    acc = b"hosec26-benign"
    for _ in range(4_000_000):  # 定数循环：结果可复现（速率另有耗时证据）
        acc = hashlib.sha256(acc).digest()
    print(f"[sample] 良性计算完成：素数 {primes} 个，哈希链 {acc.hex()[:16]}", flush=True)


if __name__ == "__main__":
    main()

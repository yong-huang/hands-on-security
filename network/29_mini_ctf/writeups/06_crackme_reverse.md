# Writeup ⑥ 逆向 crackme（150 分）

## 题目
`GET /c6/crackme` 是一个 aarch64 ELF：输对口令打印 flag。口令与 flag 都
经过 0x5A XOR 混淆，`strings` 看不到明文。

## 思路
不动新手三连（strings/objdump）先侦察，再判断混淆方式，最后写脚本还原。

## 步骤
```bash
curl -s http://127.0.0.1:8930/c6/crackme -o crackme29
file crackme29                      # ELF 64-bit LSB executable, ARM aarch64
strings crackme29 | head            # 只有 password:/wrong 等提示——明文被藏了

# objdump（容器内）看 .rodata 里的二进制数组，发现字节呈「均匀偏移」特征 → 怀疑异或
# 最快路径：全文件暴力扫描 0x5A XOR：
python3 - <<'EOF'
import re
data = open('crackme29','rb').read()
for i in range(len(data) - 8):
    dec = bytes(b ^ 0x5A for b in data[i:i+64])
    m = re.match(rb'HOSEC29\{[^}]*\}', dec)
    if m:
        print('混淆串位置:', hex(i), '→', m.group(0).decode())
EOF
```

输出 `HOSEC29{r3v3rs3_0n3_st3p}`——同一遍扫描还能顺手还原口令
`hosec29-static-key`（跑法：在 aarch64 容器里 `./crackme29` 输口令验证）。

## 关键点
- 混淆特征：XOR 后字节分布均匀，明文串消失；`0x5A` 是最常见的单字节钥匙。
- 静态可解不必运行——跨平台（本机 macOS 跑不了 aarch64 Linux ELF）也能拿
  flag，这正是实验 24「静态分析」的实战化。
- 防御视角：单字节 XOR 不叫加密；真保护要考虑反调试/加壳（实验 22/26 的
  另一面）。

## 答案
`HOSEC29{r3v3rs3_0n3_st3p}`

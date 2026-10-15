# Writeup ② MD5 弱口令（100 分）

## 题目
`GET /c2/hash` 给出 admin 的 MD5 摘要，口令取自常见弱口令。

## 思路
MD5 不可逆 → 用词典碰撞：拿常见弱口令表逐个求 MD5，与目标比对。
这正是真实世界里「撞库/彩虹表」的最小版本。

## 步骤
```bash
HASH=$(curl -s http://127.0.0.1:8930/c2/hash | python3 -c "import json,sys;print(json.load(sys.stdin)['md5'])")
python3 - <<EOF
import hashlib
target = "$HASH"
words = ["123456","password","qwerty","admin888","welcome","monkey","dragon", "..."]
for w in words:
    if hashlib.md5(w.encode()).hexdigest() == target:
        print("命中:", w); break
EOF
```

## 关键点
- 弱口令词典不需要大——Top 30 就能覆盖大量真实事故。
- 防御视角：口令存储应加盐 + 慢哈希（bcrypt/argon2），MD5 早已不适合。
- flag 是固定串（题干未提示时，可用命中口令作线索核对），提交
  `HOSEC29{w3ak_p4ssw0rd_cr4ck3d}`。

## 答案
`HOSEC29{w3ak_p4ssw0rd_cr4ck3d}`

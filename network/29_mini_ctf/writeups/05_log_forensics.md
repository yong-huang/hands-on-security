# Writeup ⑤ 日志取证（100 分）

## 题目
`GET /c5/access.log` 是一份访问日志，攻击者把 flag 编进了 URL 带出。

## 思路
攻击者外带数据最爱藏在 URL 参数里。日志里 80 行请求，肉眼看效率低——
先 grep 可疑关键字（upload / 长参数 / 百分号编码），再 URL 解码。

## 步骤
```bash
curl -s http://127.0.0.1:8930/c5/access.log > access.log

# 1) 找带长参数的请求
grep -n 'upload' access.log
# → ...03:14:07... "GET /upload?name=backup_%48%4F%53%45%43... HTTP/1.1" 200 1337

# 2) URL 解码后取 flag
python3 - <<'EOF'
import re, urllib.parse
log = open('access.log').read()
for m in re.finditer(r'HOSEC29\{[^}]+\}', urllib.parse.unquote(log)):
    print(m.group(0))
EOF
```

## 关键点
- URL 编码（`%48%4F...`）= 十六进制字节，`unquote` 一步还原。
- 真实取证还要对时间线（03:14:07 是整个日志里唯一 66 号 IP 的动作）。
- 防御：出口流量审计 + 敏感数据禁止出现在 URL（会进日志、代理、Referer）。
- 结果：`HOSEC29{l0g_f0r3ns1cs_w1ns}`

## 答案
`HOSEC29{l0g_f0r3ns1cs_w1ns}`

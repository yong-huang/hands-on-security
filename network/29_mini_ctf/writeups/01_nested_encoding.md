# Writeup ① 套娃编码（100 分）

## 题目
`GET /c1/data` 返回一长串字符，flag 被多层编码裹成洋葱。

## 思路
先摸清层数与类型：头部字符集像 base64（含 `=` 填充），解一遍还是 base64，
再解一遍仍是——「套娃」提示多层同型编码。用「解一层看一层」的方式推进。

## 步骤
```bash
curl -s http://127.0.0.1:8930/c1/data > blob.txt
python3 - <<'EOF'
import base64
data = open('blob.txt','rb').read()
for _ in range(3):
    data = base64.b64decode(data)      # 三连 base64
data = bytes.fromhex(data.decode())    # 十六进制
print(data[::-1].decode())             # 反转 → 明文
EOF
```

## 关键点
- 判层数：每次解码后看结果「还像不像可打印编码文本」——像就继续解。
- 三种层的辨别：`base64`（字母数字+`+/=`）、`hex`（0-9a-f 偶数长）、反转
  （解出来是倒序明文）。
- 结果：`HOSEC29{n3st3d_c0d1ng_l4y3rs}`

## 答案
`HOSEC29{n3st3d_c0d1ng_l4y3rs}`

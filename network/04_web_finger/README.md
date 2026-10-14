# 04 · Web 指纹识别器：响应头、HTML 特征与 favicon hash 的规则引擎

> 目标站点不会自我介绍用了什么技术栈，但响应头、页面特征与 favicon（浏览器
> 标签页上的小图标文件）会留下制式痕迹。本实验用约 130 行 requests（Python
> 的 HTTP 客户端库）代码实现指纹识别器，在三个本地样本站上达成 3/3 识别，
> 并验证 favicon 指纹同站恒定、异站不同。只打本机样本与授权目标。

## Background

没有指纹识别器之前，判断一个站点用什么搭的，只能看页脚版权、猜 URL 后缀、
翻 HTML 注释，一个站几分钟。

站点一多就撞墙：逐个翻开费时；更要命的是版本——只知道是 WordPress 还不够，
要版本号才能对上漏洞库（CVE，公开漏洞编号）。

指纹识别把过程自动化：把「框架留下的制式痕迹」（响应头、生成器标记、图标
文件）整理成规则批量匹配。Wappalyzer（浏览器插件）、WhatWeb（命令行）与
Shodan（联网设备搜索引擎）由此而来；厂商也开始主动抹除或伪造痕迹。

## What

一句话定义：Web 指纹识别器是**对目标采集响应头、HTML 特征与 favicon 等
痕迹、按规则匹配出服务器/语言/框架/CMS（内容管理系统）的工具**。

心智模型：把网站想象成现场勘查——每个框架都留下「制式零件」：Django 的
cookie 名、WordPress 的 `/wp-content/` 路径、各家 favicon 图像，识别器就是
收集零件对照图鉴。失效边界：零件能被拆掉或装假，识别就失灵。

三类信号：

| 信号 | 例子 | 特点 |
|:---|:---|:---|
| 响应头 | `Server`、`X-Powered-By`、`Set-Cookie` 名 | 一眼可见，也最常被定制或抹掉 |
| HTML 特征 | meta generator（CMS 写入 HTML 头部的生成器标记）、特征路径、注释 | 藏在正文里，改动成本高一些 |
| favicon | favicon.ico 的 md5 哈希（把任意字节压成定长的指纹值） | 图像字节恒定、最难改；代价是只认「同款」 |

## When to Use

典型场景：授权渗透侦察（先确认技术栈，再匹配攻击面）；资产盘点（发现忘了
下线的旧 CMS 实例）；漏洞响应（某组件爆出漏洞时，快速圈出受影响的站点）。

何时不用：只盘一个站点时手工更快；能先从被动源（他人已采集的数据，如证书
日志）拿到结论，就别发主动请求。浏览器插件适合浏览时顺手看，不适合批量。

| 方案 | 机制 | 什么时候选它 |
|:---|:---|:---|
| 自建识别器（本实验） | 三信号 + 规则引擎，输出证据 | 学习原理、定制内部规则 |
| Wappalyzer / WhatWeb | 成熟规则库，覆盖面广 | 想要现成广度，不想自建规则 |
| Shodan / 钟馗之眼 | 全网预扫描 + favicon 聚类 | 找「同类站点」做资产聚类 |

## Quick Start

前置：`pip3 install flask requests`（仓库根 `bash scripts/load_resources.sh`
可一键体检全部依赖）。

```bash
cd network/04_web_finger
./web_finger.sh               # apply → observe → clean 一条龙（约 5 秒）
./web_finger.sh apply         # 起样本站：8030 http.server / 8031 flask / 8032 仿真
./web_finger.sh observe       # 识别三站、断言 3/3、favicon 一致性与 curl 对照
./web_finger.sh clean         # 停样本站，端口复原
```

observe 阶段的真实输出（节选）：

```text
... # apply 段与样本 A（:8030）、B（:8031）的输出省略：A 命中 2 条、B 命中 4 条
[*] 目标 http://127.0.0.1:8032  状态 200  规则 8 条
[HEAD] Server: Apache/2.4.57 (Debian)
[HEAD] X-Powered-By: PHP/8.2.7
[HEAD] Set-Cookie: PHPSESSID=3f1c9a2b7d; path=/
[FAV]  favicon.ico 140B，md5 6a71b8570b71dec9fd125b8ea28b2df7
[HIT] 服务器 · Apache httpd  证据：Server: Apache/2.4.57 (Debian)
[HIT] 语言 · PHP  证据：X-Powered-By: PHP/8.2.7
[HIT] CMS · MockCMS  证据：HTML 含 content="MockCMS；favicon md5 6a71b8570b71dec9fd125b8ea28b2df7
[=] 完成：命中 3 条规则（服务器 1 · 语言 1 · CMS 1），耗时 0.01s
  ✅ Python http.server 静态站（:8030）命中 2/2
  ✅ Flask 博客样本站（:8031）命中 4/4
  ✅ Apache + PHP 仿真站（:8032）命中 3/3
  ✅ 三站指纹 3/3 识别正确（共 9 条规则命中）

=====> [observe] favicon hash 一致性：同一站点两次运行结果应相同
  ✅ 同一站点两次一致：18a01fae2dd175ea37c7d07d9438ad65
  ✅ 不同站点指纹不同：B=18a01fae2dd175ea37c7d07d9438ad65  C=6a71b8570b71dec9fd125b8ea28b2df7
... # 样本 A 的 favicon 标注行、curl 对照与 clean 三段省略，详见脚本本身
```

先 `./web_finger.sh apply` 起样本站后，识别器也可独立运行：
`python3 web_finger.py http://127.0.0.1:8032`（`-r` 换规则文件）。

诚实预期（新手第一个失败点）：apply 报「样本 X 4 秒内未就绪」即对应端口被
占用——`lsof -i :8030` 查占用者，或 `LAB_PORT=8040 ./web_finger.sh` 整体平移
三站端口。样本 A 没有 favicon，工具标注「未提供」而非报错，也是预期行为。

## How It Works

![Web 指纹识别流程](images/web_finger.svg)

> 怎么看：识别器向样本站发两类请求（首页 + favicon），把响应头、正文、图标
> 哈希整理成信号表交给规则引擎；命中的进报告并附证据链，全不命中的落入
> 「未匹配规则」——那是识别盲区。

> 🌐 **交互版**：本地打开 [`images/web_finger.html`](images/web_finger.html)。

**规则引擎：跨组 AND、组内 OR**：一条规则由若干条件组组成——「某个头包含
某串」「正文包含某串」「favicon md5 等于某值」。`MockCMS` 这条要求 meta 标记
与 favicon 同时命中（AND）：

```json
{ "id": "mockcms", "name": "MockCMS", "category": "cms",
  "match": { "body_contains": ["content=\"MockCMS"],
             "favicon_md5": ["6a71b8570b71dec9fd125b8ea28b2df7"] } }
```

组内给多个候选就是 OR（`server_contains: ["Apache", "nginx"]` 任一命中即可）；
所有非空组都通过才算命中，且必须附证据——每条 `[HIT]` 后的「证据」就是它，
可回原始响应逐条复核。

**favicon 为什么能当指纹**：favicon 是静态文件，同一份图在每台服务器上
字节一致，md5 哈希便恒定，实测同站恒定、异站不同。弱点是只认「同款」——
换了图标就失配。Shodan 用 32 位的 mmh3 哈希做全网 favicon 聚类，原理相同。

**样本站怎么来的**：A 是标准库 `http.server`、B 是真 Flask（Python 轻量
Web 框架）——真实组件；C 仿真 Apache + PHP 响应特征（Docker 未运行、拉不了
容器，项目 12 后换真容器）。期望与断言见 `configs/lab_expectations.json`。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **apply 报「样本 X 未就绪」**：对应端口被占用——`lsof -i :8030` 查占用者，
  或 `LAB_PORT=8040 ./web_finger.sh` 整体平移三个端口。
- **真实站点什么都没识别出**：Server 被 CDN/WAF 改写（内容分发网络 / Web
  应用防火墙）、favicon 404、正文混淆——先看 `[HEAD]`、`[FAV]` 确认采没采到。
- **版本号对不上**：同一软件不同版本的头格式有差异；规则用 contains 匹配
  主名（如 `Apache`），版本号只当参考信息。
- **curl 对照失败**：`curl -I` 发的是 HEAD 请求（只取头不取正文），个别服务不实现它——脚本改用 GET + 头转储（`curl -s -D -`）。

深入问答：

- **Q: 指纹被伪造怎么办？** A: 伪造通常只覆盖单信号——要等多信号互证后再
  下结论（头说 Apache、favicon 却属某 CMS？），单信号只当线索；输出强制附证据。
- **Q: 为什么用 md5 而不是 Shodan 的 mmh3？** A: 都是「字节 → 短指纹」；mmh3
  是 32 位非加密哈希，适合全网聚类；md5 零依赖够用，对接 Shodan 库时再换。
- **Q: 识别技术栈有什么用？** A: 攻击视角，技术栈决定攻击面（PHP 站查注入、
  WordPress 查插件漏洞）；防守视角，资产盘点发现没人维护的旧实例。
- **Q: 探测一个站点算入侵吗？** A: 发两个普通 GET（首页 + favicon），和浏览
  器访问网页相同；但它仍是主动行为、会留在对方访问日志里，未授权目标不做。

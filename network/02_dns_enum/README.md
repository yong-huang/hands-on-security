# 02 · 子域名与 DNS 信息收集器：字典枚举、记录查询与 AXFR 区域传送

> 一个域名背后往往还有几十个不对外宣传的子域——测试环境、内部接口、邮件主机。
> 本实验用 dnspython 实现子域枚举器，在权威测试域上跑通「字典爆破 → A/CNAME
> 解析 → NS/MX/TXT 查询 → AXFR 区域传送」全流程并与 dig 对照。命令只针对
> 本机测试域与公开记录，勿对未授权目标枚举。

## Background

一个域名背后通常不止一台主机：mail 收邮件、api 提供接口、staging 跑预发布，
这些名字不写在首页上，却直接对应可访问的服务——找齐它们资产面才完整。

DNS 不提供「列出所有名字」的操作：它像一本只能按名字查的电话簿，你不问它
就不说；早期只能手工逐个试名字。系统化枚举由此而来——字典批量查询候选名，
外加一个「后门」：区域传送（AXFR）配置不当时会把整个区交出来。

## What

一句话定义：DNS 信息收集器是**用字典批量探测候选子域、查询公开记录类型，
并尝试区域传送来补全目标域名资产地图的工具**。

心智模型：把 DNS 想象成只能按名查号的电话簿——枚举就是拿常见名字表挨个拨号
（www？mail？api？），有人接就记下来；AXFR 则是直接要整本号码簿，只有配置
失误的服务器才给。失效边界：字典里没有的名字拨多少次也找不到。

工具输出的五类记录：

- **A**：域名 → IPv4 地址，最核心的资产线索。
- **CNAME**：别名，链式指向另一个域名；悬空别名是子域接管漏洞的温床。
- **MX**：邮件路由；值为 `0 .` 表示此域不接收邮件（example.com 就是）。
- **TXT**：文本记录，SPF/DKIM/域验证都放这里；**NS**：权威服务器名单。

## When to Use

典型场景：

- 授权渗透的信息收集：先枚举子域圈定范围，再对命中主机做端口/Web 探测。
- 资产盘点：定期枚举自家域名，发现被遗忘的测试环境（常见的影子资产）。
- DNS 卫生检查：看 TXT 里 SPF/DMARC 是否配齐、MX 是否指向预期邮件商。

何时不用：未授权目标不枚举——批量查询会在对方 DNS 日志里留下清晰痕迹；
已经能拿被动数据时先查证书日志更安静，缺的部分再用字典补。

同类方案对比：

| 方案 | 机制 | 什么时候选它 |
|:---|:---|:---|
| 字典枚举（本实验） | 主动查询候选名字，覆盖率靠字典 | 授权范围内的精确探测 |
| 证书透明度日志（crt.sh） | 被动收集证书里出现过的域名 | 想安静拿大名单，先看这个 |
| AXFR 区域传送 | 向权威服务器要全量区数据 | 只在授权测试中，配置失误时一击全中 |

## Quick Start

前置：`pip3 install dnspython`；`brew install dnsmasq`（测试域服务器；本地
进程替代容器，原因见问答）。

```bash
cd network/02_dns_enum
./dns_enum.sh                # apply → observe → clean 一条龙（约 8 秒）
./dns_enum.sh apply          # 只起测试域：127.0.0.1:5300 的 lab.local
./dns_enum.sh observe        # 只跑枚举、dig 对照与外网对照
./dns_enum.sh clean          # 停测试域，端口复原
```

observe 阶段的真实输出（节选；[NS]/[MX]/[TXT] 段与重复断言从略，MX/TXT 取值见下方 dig 对照）：

```text
=====> [observe] 子域枚举 + NS/MX/TXT + AXFR（测试域 @127.0.0.1:5300）
[*] 目标 lab.local  解析器 127.0.0.1:5300  线程 20

[SUB] 子域枚举（字典 25 条，查 A/CNAME）
  api.lab.local                A      127.0.0.1
  blog.lab.local               A      127.0.0.1
  mail.lab.local               A      127.0.0.1
  shop.lab.local               CNAME  www.lab.local.（A: 127.0.0.1）
  www.lab.local                A      127.0.0.1
  命中 5/25，耗时 0.01s

[AXFR] 区域传送尝试 @ 127.0.0.1:5300
  ✅ 传送成功：10 条记录
  api.lab.local.                  600 IN A      127.0.0.1
  ...
  www.lab.local.                  600 IN A      127.0.0.1
  ✅ 5 个预置子域全部命中（www/mail/api/blog/shop）
  ✅ CNAME 别名链识别成功（shop → www）
  ✅ AXFR 区域传送成功（10 条记录，一次拿全）

=====> [observe] dig 对照：MX / TXT 逐条一致
  ✅ MX 一致：10 mail.lab.local.
  ✅ TXT 一致："v=spf1 -all"

... # 外网 example.com 对照与公网 AXFR 被拒演示两段省略，见脚本本身
```

枚举器也可直接当命令行工具用：

```bash
python3 dns_enum.py lab.local --resolver 127.0.0.1 --port 5300   # 打测试域
python3 dns_enum.py example.com --no-enum --no-axfr              # 只看 NS/MX/TXT
python3 dns_enum.py mycorp.com -w my.txt -t 50                   # 换字典/线程
```

诚实预期（新手第一个失败点）：apply 报「dnsmasq 4 秒内未就绪」说明 5300
被占用（`lsof -i :5300`）；外网对照依赖系统 DNS，离线环境自动跳过并标注。

## How It Works

![DNS 信息收集流程](images/dns_enum.svg)

> 怎么看：上排是工具侧——字典 → 并发探测 → 命中表，AXFR 尝试 → 全量记录；
> 中排测试域服务器应答全部查询；下排是真实环境的常态：跨域 AXFR 被拒绝。

> 🌐 **交互版**：本地打开 [`images/dns_enum.html`](images/dns_enum.html)。

**并发探测为什么快**：每个子域要问 1~2 次 A/CNAME，dnspython 的同步查询在
线程池里并发（默认 20 线程），25 条字典 0.01 秒跑完——localhost 没有网络
延迟，瓶颈只剩进程调度。每线程独立构造 Resolver，避免共享状态。

**CNAME 链怎么识别**：查询 A 时 dnspython 自动沿别名链解析到最终 A，
`canonical_name` 与查询名不一致即走过 CNAME——输出里 shop 那一行括号里的
`（A: 127.0.0.1）` 就是链尾地址。

**AXFR 的机制与真相**：区域传送是 DNS 的正常功能——主服务器把整个区同步给
从服务器，走 TCP 53 端口，没有认证，全靠 IP 白名单防守。测试域写
`auth-peer=127.0.0.1`；线上失误是写成全放行——脚本对 example.com 得到
`TransferError`，这就是正常防守。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **apply 报 dnsmasq 未就绪**：5300 被占用。`lsof -i :5300` 找占用者，
  或 `DNS_PORT=5301 ./dns_enum.sh` 换端口重跑。
- **没装 dnsmasq**：`brew install dnsmasq`，脚本不注册开机服务，随用随起。
- **dig 对照不一致**：先看两边是否都排过序；记录轮转顺序不同不代表内容不同。
- **外网对照被跳过**：系统 DNS 不通或代理干扰，离线属预期行为，联网后重跑。
- **枚举结果比预期少**：字典覆盖率决定检出率；扩充 `-w` 字典比加线程有效。

深入问答：

- **Q: 为什么用本地 dnsmasq 而不是 Docker 容器？** A: 本机 Docker daemon
  未运行且 Docker Hub 直连不通（镜像加速在项目 12 处理）；本地进程与容器版
  功能等价，配置即 `configs/dnsmasq-lab.conf`。
- **Q: NXDOMAIN 和「有名字但查不到 A」有什么区别？** A: NXDOMAIN 是名字
  根本不存在；NoAnswer 是名字存在但该类型没记录——配合 CNAME 常能发现悬空
  别名（指向已注销服务），是子域接管的线索。
- **Q: AXFR 用 TCP、普通查询用 UDP，怎么理解？** A: 单条查询小，UDP 快；
  全量区数据几十 KB 起步，必须用能分块流式传输的 TCP。
- **Q: 这样枚举会被对方发现吗？** A: 会。每条查询都落在对方 DNS 日志里，
  高频枚举非常显眼；授权测试也要控制速率，或者先走被动源。

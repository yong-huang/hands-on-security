# 20 · Suricata IDS 实战：自定义规则与离线 pcap 检测

> IDS（Intrusion Detection System，入侵检测系统）是网络层的规则引擎：把
> 流量喂给它，命中的规则记成告警。本实验在 macOS 上走离线模式（`-r` 读
> pcap——事先抓好的流量文件），自写两条规则——① SYN（TCP 握手第一个
> 标志包）扫描特征；② URI（请求行里的资源路径）含 union select（SQL
> 注入经典载荷）——对三段自造流量（含负对照：一段正常流量，验证不误报）
> 完成检出，并用 jq（命令行 JSON 处理器）从 eve.json（Suricata 的结构化
> 事件日志）机读告警。语料本地构造，全程无需 root。

## Background

实验 19 在应用日志里找攻击的形状；网络层还有一份现场：包。IDS 的价值在
于与业务解耦——不管应用怎么写日志，流量里的握手异常与 URI 特征都在那。
Suricata 是主流开源实现：规则语法接近 Snort（上一代经典开源 IDS），边解码边匹配。

macOS 没有 inline/IPS（IPS＝Intrusion Prevention System：串接在链路里、可直接丢包的防御模式）能力，所以本实验用离线 pcap 模式——
这恰好也是规则开发的标准姿势：语料固定、结果可对账，规则调试与线上同源。

## What

一句话定义：**IDS 是「流量 → 解码与流重组 → 规则匹配 → 告警输出」的
流水线**；一条规则就是流水线上的一个断言。

心智模型：机场安检机——行李（包）过传送带（解码与重组），屏幕上比对
违禁品形状（规则），命中就打标记（告警）。失效边界：规则只认识**已知
形状**——把 100 个 SYN 摊到十分钟的慢扫描、以及加密后的流量（没有明文
URI），都会从规则眼皮底下走过。

两条自定义规则（本实验的产出）：

| sid | msg | 匹配核心 | 语料 |
|:---|:---|:---|:---|
| 2000001 | SYN 扫描 | `flags:S,12` + `detection_filter count 20/5s` | scan-syn.pcap |
| 2000002 | SQLi（SQL 注入）尝试 | `http.uri` + `pcre`（正则匹配语法）`(/union[\s+]+select/i)` | sqli-union.pcap |

## When to Use

典型场景：给自建服务加一层网络检测；把攻击实验的流量回灌验证检测规则
（19-20 的闭环）；红蓝对抗（红队攻、蓝队守）演练里当蓝方哨兵。

何时不用：macOS 做不了 inline 阻断（要 Linux 内核的 AF_PACKET/NFQUEUE 抓包与包队列接口）；
纯加密流量要靠 TLS 解密或 JA3（从 TLS 握手提取的客户端指纹）之类替代指纹，不是明文规则能覆盖的。

| 做法 | 机制 | 什么时候选它 |
|:---|:---|:---|
| 自写日志审计（实验 19） | 应用日志里找形状 | 有日志可用的场景 |
| Suricata 规则（本实验） | 网络层解码 + 匹配 | 流量现场、与业务解耦 |
| 商业 NDR（Network Detection and Response：网络检测与响应） | 行为分析 + 情报 | 规模化与托管运营 |

## Quick Start

前置：`brew install suricata`；`pip3 install scapy`（构造 pcap 用）。
不需要 root、不需要靶场服务。

```bash
cd network/20_suricata
./suricata_lab.sh            # 规则自检 → 生成 pcap → 三路检测 → jq 检索（约 10 秒）
./suricata_lab.sh apply      # 只做规则自检并生成三段 pcap
./suricata_lab.sh observe    # 只跑三路检测与 jq 检索
./suricata_lab.sh clean      # 只清 artifacts
```

默认运行的真实输出（节选）：

```text
... # 输出首行空行省略
=====> [apply] 检查依赖 + 规则语法自检 + 生成三段测试 pcap
  ✅ 规则语法自检通过：2 条 alert 规则
[gen] 三段 pcap 已生成到 artifacts/pcaps/：
[gen]   scan-syn.pcap   200 包——SYN 扫描 100 端口（2 秒内）
[gen]   sqli-union.pcap  10 包——一条 union select 注入请求（负对照：benign 不应告警）
[gen]   benign.pcap       10 包——正常 GET /index.php
  ✅ 测试语料就绪（含负对照 benign.pcap）

=====> [observe] ① SYN 扫描检出：100 端口 / 2 秒的扫描被规则 2000001 接住
[run] pcap: read 1 file, 200 packets, 10800 bytes
[scan] fast.log 共 80 条告警；第 1 条：
  05/01/2026-03:00:00.400000  [**] [1:2000001:1] SCAN nmap SYN 扫描：同一来源 5 秒内高频 SYN [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 198.51.100.77:40020 -> 192.0.2.10:21
  ✅ nmap SYN 扫描特征检出（阈值第 21 个 SYN 起每条后续 SYN 都告警）

=====> [observe] ② SQLi URI 检出：union select 请求被规则 2000002 接住
[run] pcap: read 1 file, 9 packets, 801 bytes
  05/01/2026-03:00:10.065000  [**] [1:2000002:1] WEB SQLi 尝试：URI 含 UNION SELECT [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 198.51.100.88:55222 -> 192.0.2.10:8080
  ✅ URI 含 UNION SELECT 检出（HTTP 解析器直接给出 http.uri 层）

=====> [observe] ③ 负对照：正常请求零告警
[run] pcap: read 1 file, 9 packets, 739 bytes
  ✅ benign.pcap 告警 0 条——没有误报才算检测器合格

=====> [observe] ④ jq 检索 eve.json：机读口径的告警事件
[jq] scan 首条：{"sid":2000001,"sig":"SCAN nmap SYN 扫描：同一来源 5 秒内高频 SYN","src":"198.51.100.77","dst":"192.0.2.10"}
[jq] sqli 首条：{"sid":2000002,"sig":"WEB SQLi 尝试：URI 含 UNION SELECT","src":"198.51.100.88","dst":"192.0.2.10"}
  ✅ eve.json 两条告警均可被 jq 检索（验收 ②）
... # clean 段省略
```

诚实预期（新手第一个失败点）：① 规则先过 `-T` 语法自检——括号里少一个
分号引擎就直接拒绝加载；② 负对照 benign.pcap 必须**零告警**——「什么都
告警」的检测器等于没检测；③ `--runmode single` 是为输出确定性加的：多
worker 并行时告警落盘顺序随调度漂移，对账会一直对不上。

## How It Works

![离线检测流水线](images/suricata_lab.svg)

> 怎么看：三段 pcap 从左侧进（含一段负对照），经解码与流重组后逐条过
> 两条规则，命中后落成两份告警——fast.log 给人、eve.json 给机器。

> 🌐 **交互版**：本地打开 [`images/suricata_lab.html`](images/suricata_lab.html)。

**规则的解剖**：骨架是 action 协议 方向 (msg; 条件; sid; rev)。
SYN 规则用 `flags:S,12` 只认纯 SYN（ACK/RST 均不置位）；
`detection_filter: count 20, seconds 5` 是引擎内建滑动窗口——
实验 19 手写的双指针，搬进一行。

SQLi 规则用 `http.uri` 缓冲直接贴 URI 层，`pcre` 的 `[\s+]+` 同时兼容
空格与 `+` 两种分隔写法。

**从包到 URI 的链路**：先解码（Ethernet/IP/TCP），再流重组（握手 +
请求响应拼成一条流），HTTP 解析器产出 `http.uri` 这类缓冲——规则才能
「在 URI 层」匹配。这也是 sqli-union.pcap 写完整握手的原因：流没建立，
HTTP 层根本不解析。

**两个输出口径**：fast.log 一行一警、给人扫一眼；eve.json 结构化，给
jq/管道/SIEM（安全信息与事件管理平台）消费（实验 19 的延续）。同一次命中，两份记录。

**离线模式的意义**：语料固定 + `--runmode single` ⇒ 两跑输出逐字一致
——规则开发就成了写测试：改规则、重跑、diff，回归一目了然。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **规则加载失败**：先 `suricata -T -S rules/local.rules` 自检——常见错是
  括号内漏分号、pcre 斜杠不配对、sid 重复。
- **告警顺序每次不同**：多 worker 并行落盘——离线对账加
  `--runmode single`，顺序即包序。
- **规则不匹配**：默认配置（suricata.yaml）里的 `HOME_NET`（受保护网段变量）
  是 RFC1918 私有网段（10./172.16./192.168. 开头），测试网段不在其中——用 `--set vars.address-groups.HOME_NET="[192.0.2.0/24]"`
  覆盖。
- **扫描规则误报正常流量**：用 `flags:S,12` 只匹配纯 SYN、阈值别调到
  个位数——单个正常连接不该触发任何规则。

深入问答：

- **Q: 和实验 19 的日志审计什么关系？** A: 同一件事的两个数据源——
  应用日志与网络流量；交叉验证时，19 里被扫的 URI 与 20 里触发的规则
  描述的是同一批动作。
- **Q: 为什么越阈值后每条 SYN 都继续告警（本实验 80 条）？** A:
  `detection_filter` 的语义是「越过阈值即持续匹配」；要降噪换
  `threshold.config` 的 limit 模式或调阈值——告警质量比数量重要。
- **Q: 生产上怎么减少误报？** A: 三层：规则写准（flags/pcre 收紧）、
  阈值调优、白名单/抑制清单；并且拿真实流量回放做回归（本实验的
  离线模式就是最小版本）。

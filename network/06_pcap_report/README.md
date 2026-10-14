# 06 · pcap 流量分析报告生成器：协议分布、Top Talker 与明文凭据提取

> 网络故障与安全事件最终都落在同一个东西上：抓包文件（pcap，记录了链路上
> 每个包的原始字节）。本实验用约 240 行 scapy（Python 数据包工具箱）代码把
> pcap 变成一份 Markdown 报告——协议分布、Top Talker（流量大户）、HTTP 明文
> 事务与凭据提取，并用 tshark（Wireshark 的命令行版）独立复核每个数字。
> 样本 pcap 由脚本合成；真实抓包命令见 How It Works。

## Background

网络出问题时，传统做法是一台台 ping、端口探测逐个试；安全事件只能靠日志
猜。但症状的原始证据在网络里流动——「谁在和谁说话、说了什么」需要被记录。

抓包工具能录下来，但录下来的东西不好读：一次故障几万行输出、手工点开每条
流既慢又难覆盖——分析器这一层由此而来，本实验就是它的最小实现。

## What

一句话定义：pcap 分析报告生成器是**把抓包文件读成结构化统计与应用层
信息、产出可复核报告的工具**。

心智模型：把 pcap 当作事故现场的「监控录像」——分析器是回放机 + 放大镜：
先按分镜（协议）点清数量，再按人物（IP）抓出场率，最后对关键台词（HTTP
事务、表单）逐句过。失效边界：录像没拍到的（未抓到的包、加密的内容），
分析器再强也变不出来。

分析四层，每层都可复核：

| 层 | 输出 | 复核方式 |
|:---|:---|:---|
| 协议分布 | TCP/UDP/ICMP/ARP/DNS/HTTP/TLS 计数 | tshark 同名过滤器逐一对照 |
| Top Talker | 按 IP 的包数与字节数 | 换口径重算仍一致 |
| HTTP 事务 | 方法、URL、状态码按顺序配对 | 回到原始包级查看 |
| 凭据提取 | POST 表单里的用户名/口令 | 报告附来源 IP 与 URL |

## When to Use

典型场景：蓝队事件回溯（圈出告警时间点前后的抓包，看清攻击者做了什么）；
性能排障（谁是流量大户一目了然）；红队自检（确认明文探测是否暴露了敏感
内容）。

何时不用：在线持续监控用 IDS（Intrusion Detection System，入侵检测系统）；
只看几个包用 Wireshark 更快；长期建模用 Zeek（把流量转成结构化日志的引擎）。

| 方案 | 机制 | 什么时候选它 |
|:---|:---|:---|
| 自研分析脚本（本实验） | scapy 读包 + 自定义统计与提取 | 要定制口径、接入自动化报告 |
| tshark 命令行 | 现成过滤器 + 字段导出 | 一次性查询，不写代码 |
| Wireshark | 图形界面逐包查看 | 人工深挖单个会话 |
| Zeek | 流量转结构化日志 | 大规模、长期流量分析 |

## Quick Start

前置：`pip3 install scapy`；tshark 可选（装上自动做交叉验证）。

```bash
cd network/06_pcap_report
./pcap_report.sh               # apply → observe → clean 一条龙（约 3 秒）
./pcap_report.sh apply         # 只合成演示 pcap（免 root）
./pcap_report.sh observe       # 只分析并交叉验证（样本缺失会自动合成）
./pcap_report.sh clean         # 清理 artifacts/（想保留报告就别跑 clean）
```

observe 阶段的真实输出（节选）：

```text
[*] 读取 artifacts/demo-login.pcap：34 个包，跨度 0.64s
[STAT] total=34 tcp=26 udp=2 icmp=4 arp=2 dns=2 http=6 tls=1
[TALK] 10.0.0.55          32 个包     2880 字节
... # 其余 4 个 Top Talker 与 3 行 HTTP 明细省略
[ALERT] 明文凭据：admin / wrongpass（POST http://login.lab.local/login，10.0.0.55 → 10.0.0.10）
[ALERT] 明文凭据：admin / S3cret123!（POST http://login.lab.local/login，10.0.0.55 → 10.0.0.10）
[=] 报告已生成：artifacts/report.md（明文凭据 2 条）
  ✅ 明文凭据提取 2/2（成功一次、失败一次都在报告里）
... # tshark 交叉验证步骤头省略
  ✅ total/tcp/udp/icmp/arp/dns/http/tls 八项与 tshark 完全一致
```

生成的报告 `artifacts/report.md` 节选（`all` 的最后一步 clean 会清掉它——
想保留就先跑 `apply` 再 `observe`）：

```markdown
| 协议 | 包数 |
|:---|:---:|
| TCP | 26 |
... # UDP–TLS 共 6 行、「注」行、「Top Talker」「HTTP 事务」两节、各节标题行与尾部「结论与建议」节省略

| 用户名 | 口令 | 目标 | 来源 |
|:---|:---|:---|:---|
| admin | wrongpass | http://login.lab.local/login | 10.0.0.55 |
| admin | S3cret123! | http://login.lab.local/login | 10.0.0.55 |
```

诚实预期（新手第一个失败点）：样本 pcap 是**脚本合成的**（34 个包、可复现），不是嗅探抓来的——真实抓包需要 sudo tcpdump（命令见下节），分析器对两者一视同仁。

## How It Works

![pcap 分析流水线](images/pcap_report.svg)

> 怎么看：pcap 进入后先分层拆解，随后统计聚合（协议分布/Top Talker）与
> 应用层提取（HTTP 事务/凭据）展开，最后汇入 Markdown 报告；两条标注
> 「tshark 对账」的边表示数字有独立复核。

> 🌐 **交互版**：本地打开 [`images/pcap_report.html`](images/pcap_report.html)。

**分层拆解与统计口径**：rdpcap 把文件读成一串包对象，每个包用 `haslayer()`
逐层询问——`[STAT]` 行的每个数都对应这几行代码：

```python
c["tcp"] = sum(1 for p in pkts if p.haslayer(TCP))
c["http"] = sum(1 for p in pkts if p.haslayer(HTTPRequest) or p.haslayer(HTTPResponse))
```

**凭据提取**：只对 POST 正文做表单解析（`urllib.parse.parse_qs`），字段名
命中 `username/password/passwd` 等别名才记录。报告里失败尝试与成功尝试
都在——错的口令一样被录下来，这正是明文传输的代价。

**为什么数字可信**：统计最怕「自己数错还理直气壮」，所以每个数字都拿
tshark 的独立实现复算：同一 pcap 分别过 `[STAT]` 与 `tshark -Y <协议>`
过滤器，八项全等才算过（本机实测 8/8）。这是实验 01（nmap 对照）、02
（dig 对照）延续的模式：自研工具与权威工具双轨互证。

**真实抓包怎么录**（需要 sudo；靶服务可先用 `python3 -m http.server` 起在 8060）：

```bash
sudo tcpdump -i lo0 -w real.pcap port 8060
curl "http://127.0.0.1:8060/login" -d "username=admin&password=S3cret123!"
python3 pcap_report.py report real.pcap -o real-report.md
```

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **tshark 一步被跳过**：没装 Wireshark CLI——`brew install wireshark` 后重跑。
- **大文件内存爆**：rdpcap 整包载入内存；GB 级 pcap 改流式 `PcapReader` 读。
- **HTTPS 里什么都提不出**：TLS 只有密文——这本身就是结论。
- **自定义表单字段漏报**：叫 `usr`/`secret` 时不命中别名——在 `CRED_USER_KEYS` 里扩展。

深入问答：

- **Q: 为什么不用 Wireshark 的导出功能？** A: 一次性看可以；要每天跑、
  按固定口径出报告、接进工单系统，就需要脚本——本实验是那个脚本的种子。
- **Q: 合成样本会不会掩盖真实世界的脏数据？** A: 会简化（真实 pcap 有
  重传、乱序、截断）。所以口径设计成对任何 pcap 都成立：统计不依赖顺序，
  提取容忍解析失败。
- **Q: pcap 里的时间戳怎么读？** A: 存的是 UTC 纪元秒（从 1970-01-01 起计的
  秒数）；报告用相对跨度避免时区歧义，跨机器对比时再转绝对时间。
- **Q: 分析别人的抓包文件有法律风险吗？** A: 抓自己设备的流量没问题；
  抓共享网络里他人的流量在多数司法辖区违法——授权边界先于技术。

# 21 · Zeek 流量分析：C2 心跳检测与 DGA 疑似识别

> Zeek（把网络流量整理成结构化日志的分析框架）是 IDS（Intrusion Detection
> System：入侵检测系统）的「日志派」：不急着匹配特征，先把流量记成一张张
> 表格（conn/dns/http.log），再让分析脚本自己判断。本实验用 scapy 离线
> 构造一段「被植入」的流量——每 30 秒等长回连的 C2（Command and Control：
> 攻击者控制受害主机的服务器）心跳 + 一批随机域名查询——用 zeek 产出日志，
> 再写分析器标出 beacon（心跳：固定周期回连的痕迹）、DGA（Domain
> Generation Algorithm：恶意程序批量生成的随机域名）疑似，并用 UA
> （User-Agent：请求头里客户端自我标识的字段）Top5 与 awk 对账。
> 全程离线、无需 root。

## Background

检测侧已经读过两本账：实验 19 看应用日志（窗口数频率）、实验 20 用规则
匹配流量特征。但高级威胁的 C2 流量没有固定特征——加密、低频、域名看着
人畜无害，唯一藏不住的是**统计规律**：它太规律了，回连的时间间隔像一个
节拍器。

Zeek 的哲学是「结构化记账」：把 pcap 变成 conn/dns/http 三段日志，之后
的检测在你熟悉的工具里进行（grep / python / jq）——这不正是实验 19
那套审计器渴求的输入吗。

## What

一句话定义：**beacon 检测是对「源 IP + 域名」分组的请求间隔做统计**——
均值告诉你周期，标准差（jitter）告诉你它是不是机器。

心智模型：心跳像假装从容的间谍——固定每 30 秒碰头、每次说一样长的话；
不隐蔽的恰恰是「规律」本身。失效边界：心跳可以加抖动、变长度、换信道
（DNS 隧道）；DGA 检测是启发式（概率提示不是判决），真实环境要配情报
与模型。

| 检测对象 | 信号 | 本实验数据 |
|:---|:---|:---|
| C2 心跳 | 间隔标准差 jitter 极小 | 30.0s 周期 ±0.10s |
| C2 心跳 | 载荷长度恒定 | 26B 请求 / 2B 应答 |
| DGA 域名 | 随机型长标签 | 3 个 `*.net/.top` |
| 对账基线 | UA 计数 vs awk | Top5 逐条一致 |

## When to Use

典型场景：企业出口流量审计；应急响应拿到 pcap 先过一遍 zeek 出日志再查；
红蓝对抗里验证「心跳够不够隐蔽」。

何时不用：全量抓包成本高时先聚合流量元数据（beacon 统计只依赖时间戳与
连接元数据，加密与否都可用）；内容层的威胁仍需实验 20 的规则或解密。

| 做法 | 机制 | 什么时候选它 |
|:---|:---|:---|
| 应用日志审计（实验 19） | 有日志可看 | Web/主机侧 |
| Zeek 结构化日志（本实验） | 流量记账 + 统计 | 网络侧、批量取证 |
| 规则匹配（实验 20） | 特征断言 | 已知形状的快速告警 |

## Quick Start

前置：`brew install zeek`；`pip3 install scapy`（构造 pcap 用）。不需要
root、不需要外部网络。

```bash
cd network/21_zeek
./zeek_lab.sh            # 生成 pcap → zeek 重放 → 三路分析 → 报告（约 10 秒）
./zeek_lab.sh apply      # 只生成 pcap 并跑 zeek 产出日志
./zeek_lab.sh observe    # 只跑心跳/UA/DGA 分析与报告
./zeek_lab.sh clean      # 只清 artifacts
```

默认运行的真实输出（节选）：

```text
... # 输出首行空行省略
=====> [apply] 检查依赖 + 生成 C2 心跳 pcap + zeek 离线重放产出日志
[gen] c2-beacon.pcap（432 包）→ artifacts/pcaps/
[gen] 植入：10.20.30.40 → beacon.cdn-analytics.net 每 30s 一次等长 POST（7 次心跳）
[gen] 正常流量：39 次浏览 + 3 个随机域名查询
  ✅ zeek 日志就绪：conn / dns / http（http 46 条请求）

=====> [observe] ① C2 心跳检测：按（源IP+域名）聚合，算间隔均值与标准差
[beacon] 候选组 7 个（按 源IP + 目标域名 聚合）
[beacon] ⚠️ beacon.cdn-analytics.net → 203.0.113.99：7 次请求，平均间隔 30.0s，标准差 0.10s（来源 10.20.30.40）
[beacon] 判定（≥5 次且标准差 ≤2.0s）：beacon 1 个
  ✅ beacon 域名标出：30s 周期、标准差 <2s（验收 ①）

=====> [observe] ② UA Top5 对账：工具统计与 awk 手工统计逐条一致
  ↳ 前 2 行：12 Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebK … / 9 Mozilla/5.0 (Windows NT 10.0; Win64; x …
  ✅ UA Top5 与 awk 手工统计逐条一致（验收 ②）

=====> [observe] ③ DGA 疑似：长标签 + 含数字 + 元音稀少的查询
[dga] DNS 查询 9 条；随机型长标签命中 3 个：
  ⚠️ xj3kq9wzmv7p.net
  ⚠️ kq7mz4tpl2.top
  ⚠️ v8nq3xzr9km.net
  ✅ 随机域名标出、正常域名零误报

=====> [observe] ④ 分析报告：beacon / UA / DGA 汇总为 Markdown
[report] 已生成 artifacts/zeek-report.md（beacon 1 / UA 7 种 / DGA 3 个）
  ✅ 报告就位：结论 / 心跳 / UA / DGA 四节（artifacts/zeek-report.md）
... # clean 段省略
```

诚实预期（新手第一个失败点）：① 检测靠的是**时间戳统计**，不是内容——
等长载荷只是锦上添花；② UA 对账的列号要从 `#fields` 表头动态取，别硬
编码（zeek 日志字段随版本增删）；③ 本实验 pcap 由 scapy 构造、时间戳
排序后写盘——重放即复现，这正是离线分析换来的确定性。

## How It Works

![C2 心跳现场](images/zeek_lab.svg)

> 怎么看：上半段是心跳的完整循环（解析域名 → 等长 POST → 等长应答 →
> 30 秒后重复），下半段是同时期的 DGA 查询（随机域名均得到「域名不存在」应答）。

> 🌐 **交互版**：本地打开 [`images/zeek_lab.html`](images/zeek_lab.html)。

**beacon 检测的算法**：按（源 IP, 域名）分组 → 时间戳排序 → 相邻差值 →
均值与标准差。为什么用标准差而不是「平均间隔接近 30s」：抖动才是签名
——人刷网页的间隔均值也可能凑出 30s，但标准差会大一个量级。本实验
阈值：≥5 次且 jitter ≤2s；命中 1 组、误报 0 组。

**Zeek 的日志体系**：conn.log 记「谁和谁连了」（五元组：源/目的 IP、
源/目的端口、协议）、dns.log 记「查了什么」（含应答码 rcode——NXDOMAIN
即「域名不存在」）、http.log 记「聊了什么」（Host/URI/UA：站点、资源
路径、客户端标识）。

格式方面：TSV（制表符分隔的表格文本）看 `#fields` 表头，JSON 每行
一个对象——同一份数据两副面孔。

**DGA 启发式**：DGA（Domain Generation Algorithm：恶意程序批量生成的
随机域名）的简化特征——标签长度 ≥10、含数字、元音稀少。它抓的是「随机
感」，真实 DGA 会用词典拼接对抗；所以输出是「疑似清单」，配合报告与
人工复核。

**对账与报告**：UA Top5 由脚本与 awk 两条路各算一遍逐条 diff（口径一致
才算数）；report 子命令把三路检测汇成 Markdown——结论、心跳表、UA 表、
DGA 清单，一气呵成。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **心跳漏报**：`--min-hits` 太大错过短窗口、太小被随机波动误报——
  阈值是价值观问题，本实验 5 次/2 秒在两组数据上都干净。
- **分组键选错**：按「目的 IP」分组会把 CDN 上多个域名混在一起——
  按源 IP + 域名才隔离出单条心跳。
- **UA 对账列号漂移**：直接数第 13 列会在 zeek 版本升级后失效——从
  `#fields` 表头解析列号（脚本就是这么干的）。
- **时间戳乱序**：构造 pcap 时忘排序，间隔统计全线失真——写盘前
  `sort by time` 是纪律。

深入问答：

- **Q: 心跳加了抖动还检测得到吗？** A: 更难但非无解——拉长统计窗口、
  多特征融合（载荷长度分布、目的集中度），或依赖威胁情报的黑名单。
- **Q: 为什么用 Zeek 而不是 Wireshark？** A: Wireshark 给人看、Zeek 给
  机器看：批量重放与自动化的输入正是这些日志。
- **Q: DNS 隧道怎么检测？** A: 同族统计——子域标签长度异常、查询量、
  唯一域名数骤增；本实验的 DGA 检测是它的小表弟。

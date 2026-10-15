# 🔐 network：动手学安全 30 实验（本地全栈 · Docker）

> 清单来源：[docs/security.md](../docs/security.md)（30 项目，一条不落）。
> 内容路线：侦查 → 密码学 → Web → 蓝队 → 二进制 → 综合实战收官。
> 与兄弟系列：hands-on-kubernetes / hands-on-devops 打工程地基（26–30
> 与容器应用线直接互补）；hands-on-reverse-eng 与 24/25 互为深挖。
> 共享资产：DVWA 栈（12 起）、node_modules（14/29 无头浏览器）、trivy
> 库缓存（28）、dnsmasq 域（02/30）。统一结构：生命周期脚本 + 六段式
> README + 图三件套。
> 环境一条命令：`bash scripts/load_resources.sh`。

进度：**30/30 (100%)** ▰▰▰▰▰▰▰▰▰▰

## 🚀 快速开始

前置：macOS（Apple Silicon）+ Docker（OrbStack / Docker Desktop）+ brew
（dnsmasq / trivy / zeek / suricata / jq）+ Python3。开工前先体检：

```bash
bash scripts/load_resources.sh        # 10 秒环境体检（缺什么补什么）
cd network/01_tcp_port_scanner
./tcp_port_scanner.sh                 # 默认 all；生命周期 apply 备靶 → observe 跑主线断言 → clean 清产物
```

诚实预期（新手第一个失败点）：首次 apply 有下载（镜像/apt/漏洞库，
1–3 分钟）；12 起需 Docker 常驻；个别实验等真实节拍（27 cron 班车
≤1 分钟，设计如此）。

## 📚 实验总表

| # | 实验 | 一句话产出 | 验收亮点 |
|:---|:---|:---|:---|
| 01 | [端口扫描](01_tcp_port_scanner/README.md) | 多线程 TCP connect 扫描器 | 与 nmap 开放端口集合全一致（12 个） |
| 02 | [子域枚举](02_dns_enum/README.md) | 权威域 + 字典 + AXFR | 5 子域 + CNAME 链 + 整区泄漏 |
| 03 | [目录爆破](03_dir_brute/README.md) | 软 404 过滤 + 一层递归 | 13 条预置路径全命中且无多余 |
| 04 | [Web 指纹](04_web_finger/README.md) | 本地靶站组件识别 | 3/3 识别正确（9 条规则命中） |
| 05 | [抓包工具](05_packet_tool/README.md) | scapy 收发与三层解析 | 三包 craft 反解析（免 root）；②③④ 需 sudo |
| 06 | [pcap 报表](06_pcap_report/README.md) | 协议分布/Top Talker/凭据提取报告 | 与 tshark 对账 |
| 07 | [哈希破解](07_hash_crack/README.md) | 识别 + 字典 + 规则 | 10/10 破出；hashcat 复核一致 |
| 08 | [AES 模式](08_aes_modes/README.md) | ECB/CBC/GCM 对比 | ECB 重复块泄漏（6552）可视化对照 |
| 09 | [RSA 混合](09_rsa_hybrid/README.md) | 教科书攻击沙盘 | 教材样例复算 + 信封完整性对账 |
| 10 | [CA/TLS](10_ca_tls/README.md) | 自建 CA 与证书链 | 三信任场景 + openssl verify |
| 11 | [JWT](11_jwt_lab/README.md) | 伪造三类手法 | none 攻破 + 弱密钥爆破命中 + 强靶三连拒 |
| 12 | [DVWA 栈](12_dvwa/README.md) | php82 + mysql 双容器栈 | compose 一键 + 建库/切档/改包重放 |
| 13 | [SQL 注入](13_sqli/README.md) | 手注 vs sqlmap | low/medium 五点检测 + sqlmap 对账 |
| 14 | [XSS](14_xss/README.md) | 三型 + 无头浏览器机器人 | 4 条回调实录 |
| 15 | [CSRF/SSRF](15_csrf_ssrf/README.md) | 伪造请求 + 内网探测 | medium Referer 绕过原理 + 3306 判定 open |
| 16 | [上传+Webshell](16_upload_webshell/README.md) | 三关绕过拿 shell | MIME / 扩展名 / 内容三关绕过 |
| 17 | [爆破+会话](17_brute_session/README.md) | 口令爆破 + 三层防护全拦 | 命中 + 时区 bug 修复实录 |
| 18 | [命令注入](18_cmd_injection/README.md) | 通关 + 渗透报告 | 213 行报告；high 通关 |
| 19 | [日志审计](19_log_audit/README.md) | 爆破检测规则引擎 | R1–R6 命中 + 报告 |
| 20 | [Suricata](20_suricata/README.md) | 自建规则 + 流量回放 | 报警逐条对账 |
| 21 | [Zeek](21_zeek/README.md) | conn/http/dns 日志分析 | beacon 30s 周期 ±2s + UA Top5 逐条一致 |
| 22 | [YARA](22_yara/README.md) | 三规则扫样本 | 3/3 检出零误报；10000 文件 0.38s |
| 23 | [应急响应](23_ir_drill/README.md) | 五后门靶机取证 | 5/5 检出；基线 0 误报 |
| 24 | [二进制静态](24_binary_intro/README.md) | 手拆 ELF + crackme | 7/7 字段对账；三重复核 |
| 25 | [栈溢出](25_stack_overflow/README.md) | ret2win 利用链 | 读出 flag；canary 对照必败 |
| 26 | [行为沙箱](26_sandbox/README.md) | 三路监控画像 | 7 类检出 115 分；良性 0 |
| 27 | [提权攻防](27_privesc/README.md) | SUID/sudo/cron 三路 | 3/3 拿 root；与 find 对账 |
| 28 | [容器审计](28_container_audit/README.md) | 配置 × CVE 双引擎 | 三件套全检出；189 个 HIGH+ |
| 29 | [mini-CTF](29_mini_ctf/README.md) | flask 平台六关 | 6/6 判分通过；750 分计分板 |
| 30 | [工具箱](30_toolbox/README.md) | 五合一 sectool CLI | 冒烟三连绿（6/0） |

## 🧭 学习路线

六阶段、编号即顺序：① 侦查与流量（01–06）→ ② 密码学与认证（07–11）
→ ③ Web 靶场（12–18）→ ④ 蓝队防御（19–23）→ ⑤ 二进制与系统（24–27）
→ ⑥ 云安全与综合实战（28–30）。

## 🖼️ 架构图

每实验 `images/` 三件套：图源 json + 交互版 html（双击即用）+ 静态版 svg。

## ⚠️ 预期失败诚实标注

- **设计为「红」**：25 canary 必失败、26 良性必 0、29 错旗必 wrong、23 基线必 0——红对才是验收。
- **环境性降级**：05 免 root 只跑第①步（②③④ 需 sudo）；25 栈帧为 arm64 原生布局（x29/x30）。
- **故意留的洞**：16 webshell、25 gets、27 提权路径——仅存本地容器靶场。

## 🔧 环境要求

- Docker：OrbStack / Docker Desktop（12 起常驻）
- brew：nmap、dnsmasq、sqlmap、john、hashcat、gobuster、suricata、zeek、trivy、jq
- Python3：requests、dnspython、cryptography、PyJWT、bcrypt、scapy、yara-python、flask、pillow、dpkt、pwntools
- Node + Chrome：14 / 29 的无头浏览器脚本（复用系列 node_modules）

## 🧪 本机实测基线

Docker/OrbStack（arm64）✅ 原生容器全流程；scapy/zeek/suricata/yara/jq ✅
版本对账；pwntools/trivy/dnsmasq/puppeteer ✅ 实机跑通。

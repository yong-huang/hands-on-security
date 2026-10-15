# 🔐 hands-on-security：把安全学成 30 个能跑的动手实验

> 一条实验线、30 个实验，全部真机跑通、免费本地可复现。每个实验统一
> 结构：`apply / observe / clean` 生命周期脚本 + 六段式 README +
> 交互式架构图三件套（json / html / svg）。

## 🗺️ 实验线总表

| 线 | 栈 | 一句话内容 | 进度 |
|:---|:---|:---|:---|
| 🔐 [network](network/README.md) | Docker · Python · scapy/zeek/suricata/yara · pwntools | 网络侦查 → 密码学 → DVWA Web 靶场 → 蓝队防御 → 二进制 → 云安全与综合实战 | **30/30 ✅** |

单线仓库：按编号顺序（01 → 30）推进即可，无需选线。清单文档：
[docs/security.md](docs/security.md)（30 项目逐项对应）；共享资产：
`scripts/load_resources.sh` 一条命令体检公共依赖（Python 包 + brew
CLI + Docker 三张清单）。

## 🚀 快速开始

```bash
bash scripts/load_resources.sh                 # 环境体检：Python 依赖 / brew 工具 / Docker
cd network/01_tcp_port_scanner
./tcp_port_scanner.sh                          # 从第一课开始（默认 all）
```

每个实验同一套生命周期：`apply`（备靶）→ `observe`（跑主线并断言）→
`clean`（清产物，缓存保留）。各实验的入口命令见其 README 的 Quick Start。
起步建议：按 01 → 30 推进；想先看效果可从 25（栈溢出）或 29（mini-CTF）入手。

## ⚠️ 预期失败诚实标注

部分实验的「红」是教学设计——25 canary 必失败、26 良性必 0、29 错旗必
wrong；免 root / 架构差异有明示降级（05、25）。

跨线注意点：首次 apply 有下载（1–3 分钟）；12 起 DVWA 需 Docker 在线。
逐线细节见 [network/README.md](network/README.md)。

## 🔧 环境要求

- macOS（Apple Silicon）：Docker（OrbStack 或 Docker Desktop）
- brew：`nmap`、`dnsmasq`、`sqlmap`、`john`、`hashcat`、`gobuster`、
  `suricata`、`zeek`、`trivy`、`jq`
- Python3：`requests`、`dnspython`、`cryptography`、`PyJWT`、`bcrypt`、
  `scapy`、`yara-python`、`flask`、`pillow`、`dpkt`、`pwntools`
- Node + Chrome：14 / 29 的无头浏览器脚本（复用系列 node_modules）

## 📝 来源与许可

清单来源：[docs/security.md](docs/security.md)（30 项目，完成勾选留
使用者自理）。使用边界：全部实验限定本地自建靶场，渗透/攻击技术仅限
授权测试（与清单文档的合法使用声明一致）。代码与文档供学习用途；
许可暂未指定（未定）。

# 27 · Linux 提权攻防：SUID / sudo / cron 三条通往 root 的路

> 实验 26 刚学会「看行为」；这节课站到攻击面：拿到一个低权 shell 之后
> 怎么变 root？靶机预埋了三条真实世界最常见的路——SUID 副本（文件带着
> root 的权限位）、sudo 误配（NOPASSWD 直通 awk，等于白送 root 壳）、
> cron PATH 劫持（root 班车从低权用户目录解析命令）。低权扫描器
> （linpeas 思路：枚举万事、只报基线偏差）把三条逐一找出，并与手工
> `find / -perm -4000` 逐项对账；再逐一利用——**3/3 拿到 id -u=0**。
> 根因一句话：系统把 root 的信任，借给了不该信任的输入。

## Background

拿到低权 shell 只是上半场——攻击者的下一句话通常是「我是谁、我能动
什么」；提权（privilege escalation）就是这下半场。而三条预埋路径全是
真实世界的翻车常客：多复制了一份 SUID、sudoers 里图省事写了 NOPASSWD、
cron 的 PATH 在排错时被随手加过用户目录。

linpeas（Linux 提权枚举脚本）的思路值得学：不猜「什么有问题」，而是
枚举一切、与基线对比——偏差就是信号。本实验用约 230 行复刻这个思路。

## What

一句话定义：**提权 = 用低权身份，借配置错误的「信任」执行 root 代码**。

心智模型：系统是一栋楼，root 是顶层机房——SUID / sudo / cron 本是三条
「内部通道」，只该对特定人开；配置错了，就成了谁都能走的门。

失效边界：三条路是「最常见」而非「全部」（还有内核漏洞、Linux
capabilities（把 root 权限拆成细粒度能力位、可单独授予的机制）、可写
systemd 单元……）；且默认经典权限模型——SELinux / AppArmor 全开时
会再添一道锁。

| 路径 | 机制 | 利用手法 | 本实验证据 |
|:---|:---|:---|:---|
| SUID 副本 | 执行时 euid（有效用户 ID）=0 | find -exec sh -p 保留 euid | id -u → 0 |
| sudo NOPASSWD | 免密授权给可逃逸程序 | awk system() 逃逸 | id -u → 0 |
| cron PATH | root 任务从可写目录解析命令 | 植入同名脚本等班车 | id -u → 0 + rootbash |

## When to Use

典型场景：CTF / 渗透「拿 shell 之后」的标准曲目；机房基线加固前，先
知道哪些口子最常被踩；读懂 linpeas 之类枚举脚本的输出。

何时不用：提权的前提是「已经进来」——它防不了入口，配合 26 的行为监控
才算闭环（那边看动作、这边看门锁）；简单手法在加固系统上失灵时，要转
内核利用——那是另一个量级的课题。

| 做法 | 机制 | 什么时候选它 |
|:---|:---|:---|
| 手工排查（find / sudo -l） | 几条命令定重点 | 有明确怀疑方向时 |
| linpeas 全量枚举 | 穷举 + 基线对比 | 陌生环境常规开局 |
| 本节扫描器（精简版） | 读得懂的 linpeas | 学原理 / 定制自己的检查 |

## Quick Start

前置：Docker（首次经 apt 构建靶机镜像，约 1–2 分钟）；宿主机 Python 3
（仅标准库，做对账断言）。
注意：③ 号利用要等 cron 班车（每 60 秒一班），观察期请耐心。

```bash
cd network/27_privesc
./privesc_lab.sh            # 扫描 → 与 find 对账 → 三路拿 root（约 1–2 分钟）
./privesc_lab.sh apply      # 只构建并启动预埋靶机
./privesc_lab.sh observe    # 只跑三步观察（需先 apply）
./privesc_lab.sh clean      # 移除靶机容器并清理产物（镜像保留）
```

默认运行的真实输出（节选）：

```text
... # 输出首行空行省略
=====> [apply] 检查 Docker → 构建预埋靶机 → 启动（cron 常驻发车）
  ✅ 靶机镜像已构建（ubuntu 22.04 + sudo/cron/python3，构建期预埋 3 条提权路径）
  ✅ 靶机已启动：cron 班车每分钟发车；主机名固定（sudo 输出可逐字对账）

=====> [observe] ① 低权视角扫描：SUID 偏差 / NOPASSWD / cron 可劫持 / 可写敏感文件
[27] 提权点扫描 · 当前用户 lowuser（uid=1000）

== ① SUID/SGID：共 15 个（SUID 10 / SGID 5；白名单外 1 个） ==
  [!] /usr/local/bin/findroot（SUID 0o4755 uid=0）——白名单外，且与 /bin/find 字节一致 → GTFOBins 可直接逃逸
  ✓ 其余 14 个与发行版默认白名单一致

== ② sudo 规则（sudo -n -l） ==
  [!] NOPASSWD: /usr/bin/awk → GTFOBins 可逃逸（如 awk 'BEGIN{system("/bin/sh")}'）

== ③ cron 审计（/etc/crontab + /etc/cron.d/*） ==
  [!] /etc/cron.d/daily-backup：命令 daily-backup 的解析目录 /home/lowuser/bin 不存在但可由当前用户创建——建成并植入同名文件即劫持（发车用户 root）
  ✓ /etc/crontab：未发现可劫持点
  ✓ /etc/cron.d/e2scrub_all：未发现可劫持点

== ④ 可写敏感文件 ==
  ✓ /etc/passwd、/etc/sudoers、cron 配置等均不可写

== ⑤ 修复清单 ==
  1) 移除白名单外 SUID：rm 或 chmod u-s（SUID 副本是 GTFOBins 的第一入口）
  2) visudo 收紧：删掉 NOPASSWD 直通可逃逸程序，改用不可逃逸的专用包装脚本
  3) cron 任务 PATH 只留 /usr/bin:/bin，命令一律绝对路径，脚本 755 root:root
  4) 回归：本脚本重跑应 0 告警——修复前先立「准入线」

检出：白名单外 SUID 1 个 / NOPASSWD 1 条 / cron 可劫持 1 处 / 可写敏感文件 0 个
  ✓ 检出：白名单外 SUID 1（findroot）/ NOPASSWD 1（awk）/ cron 可劫持 1（daily-backup）
  ✅ 三条预埋路径全部命中，无多余误报（验收：检出与预埋一致）

=====> [observe] ② 手工对照：find / -perm -4000 与扫描器清单逐项比对
  ↳ /usr/bin/chfn
  ↳ /usr/bin/chsh
  ↳ /usr/bin/gpasswd
  ↳ /usr/bin/mount
  ↳ /usr/bin/newgrp
  ↳ /usr/bin/passwd
  ↳ /usr/bin/su
  ↳ /usr/bin/sudo
  ↳ /usr/bin/umount
  ↳ /usr/local/bin/findroot
  ✓ 两份清单完全一致：共 10 个 SUID（含 1 个白名单外偏差）
  ✅ 检测脚本输出与手工排查结果一致（验收：与 find 对得上才算数）

=====> [observe] ③ 利用演示：三条路径逐一拿到 root（cron 需等下一班车，最长约 1 分钟）
① SUID find 副本：id -u => 0
② sudo NOPASSWD awk：id -u => 0
③ cron PATH 劫持：id -u => 0
   └ rootbash 副本（SUID）：id -u => 0
  ✅ 3/3 路径全部拿到 root（id -u=0；另留 rootbash 副本一枚）——验收要求 ≥2/3

=====> [clean] 移除靶机容器并清理产物（镜像保留，重跑秒级）
  ✅ 容器与产物已清；靶机镜像 hosec27-target 保留
```

诚实预期（新手第一个失败点）：① 等车是设计不是卡死——cron 的最小粒度
就是 1 分钟，晚埋一班、多等一分；② 白名单有版本敏感性——换发行版或
装新包都会动基线，先取基线再谈偏差；③ 攻防要成对：修复清单不是摆设，
改完重扫应为 0 告警（准入线纪律，与实验 23 / 26 一脉）。

## How It Works

![三条通往 root 的路：SUID / sudo / cron 提权链](images/privesc.svg)

> 怎么看：三条泳道各是一条完整的提权链——预埋（红）→ 低权检测（绿：
> 白名单外 SUID / NOPASSWD / cron 可劫持）→ 利用得手（蓝：id -u=0）。
> 交互版图下方还有三张卡片：三条路的共性与验收纪律。

> 🌐 **交互版**：本地打开 [`images/privesc.html`](images/privesc.html)。

**SUID：副本才是信号**：SUID 让文件以文件主身份跑；文件主是 root 时，
执行者借到 euid=0。白名单外的**副本**（与 /bin/find 字节一致）才是
信号——照搬 GTFOBins（合法工具逃逸的公开配方）：find -exec /bin/sh -p
（-p 保住 euid）。

**sudo：授权对象错了**：NOPASSWD 本身不是错，错在授权给图灵完备的
解释器——awk 能 system()、python 能 os.system、find 能 -exec：给命令
的皮，等于给 shell 的骨。

**cron：路径是关键**：cron 任务行里的命令若不含路径，就从任务自带的
PATH 逐目录解析——一旦可写目录排在前面，植入同名文件即劫持（低权用户
「建目录」这一手也算——扫描器连「目录不存在但可创建」都要报）。这道门
是三条里最好关的：PATH 只留系统目录、命令一律绝对路径。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **以为脚本卡死了**：③ 号利用在等 cron 班车（60 秒粒度）——等待循环
  是设计；晚埋一班就多等一分钟。
- **SGID 不是 SUID**：SGID 是「执行时借文件属组身份」（对照 SUID 借
  文件主）；chage/crontab 等默认带 SGID（shadow 组），白名单要两套；拿
  `-perm -4000` 的口径去对 SGID 会错位。
- **基线不可死记**：最小安装与装包集合都会动白名单——扫描器报「偏差」
  之前，先确认你的基线是本机的。
- **等错车次**：埋马时机晚于本分钟发车点，就要再等满一轮——测试环境
  里这是「利用失败」的头号假阳性。

深入问答：

- **Q: 为什么「find 副本」比「find 本身」典型？** A: 发行版不会给 find
  配 SUID；副本几乎都是管理员手误（备份、排错时 cp 出来的）。
- **Q: 这些错误现实中常见吗？** A: cron PATH 与 sudo NOPASSWD 是提权
  实战的 top 手法，GTFOBins 网站专门收录了数百个可逃逸程序。
- **Q: rootbash 是什么尾巴？** A: 克隆一份带 SUID 位的 bash——留后门、
  拿交互 root shell 的经典动作，也是入侵检测的重点观察对象。

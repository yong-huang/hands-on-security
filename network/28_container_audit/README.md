# 28 · 容器安全审计器：配置危险项 × 镜像 CVE 双引擎

> 实验 27 在 Linux 主机上提权；这节课把「危险」带上容器层。审计器装了两
> 台引擎：一台读 `docker inspect`，用 9 条规则查「等于宿主 root」的配置
> （privileged、挂 docker.sock、host 网络……每条附修复动作）；另一台让
> trivy（开源漏洞扫描器）把镜像里每个软件包与漏洞库（每个已知漏洞一个
> 通用编号，即 CVE）逐一比对，汇总 HIGH+ 条目。三条验收：危险容器三件套**全检出**（评分 116 → 高危）、全加固
> 容器 **0 告警**、EOL（停止维护）镜像 nginx:1.19 汇总出 **189 个
> HIGH+**。

## Background

容器让人产生「里面很安全」的错觉，但隔离强度全看配置：privileged 与挂
docker.sock 这两项，任何一个都能把容器径直送回宿主 root——实验 27 的三
条路在容器里同样成立，只是入口换成了编排参数。

镜像侧是另一条供应链：基础镜像一旦停更，漏洞只积不修——
nginx:1.19 停在 2021 年，扫描器一眼读出 189 个 HIGH+。配置与 CVE 是两种
独立风险，这正是双引擎的意义。

## What

一句话定义：**容器审计 = 检查「隔离强度」与「镜像成分」两本账**。

心智模型：容器像码头上的集装箱——配置是箱门的锁（privileged / socket /
host 网络就是被拆掉的锁），镜像成分是箱内货物（EOL 镜像=过期危化品）。

失效边界：审计只覆盖「已知配置项 + 已知 CVE」——镜像里嵌的恶意代码要
靠实验 26 的行为沙箱，内核漏洞逃逸超出本节；另注意 CVE 命中 ≠ 可利用
（还要看漏洞组件是否真的可达）。

| 引擎 | 输入 | 看什么 | 输出 |
|:---|:---|:---|:---|
| 配置审计 | docker inspect JSON | 9 条危险项规则 | 评分 + 修复动作 |
| CVE 审计 | 镜像层（trivy） | 包 × 漏洞库比对 | HIGH+ 计数 + TOP 清单 |

## When to Use

典型场景：新容器上线前的体检；CI 里加 `trivy image --exit-code 1
--severity HIGH,CRITICAL` 卡口；
接手机房时给存量容器做盘点。

何时不用：本地随手开的开发容器不必次次审计（成本大于收益）；「CVE 数
为零」也别当免死金牌——静态扫描不回答「能不能打进来」。

| 做法 | 机制 | 什么时候选它 |
|:---|:---|:---|
| `docker inspect` 肉眼查 | 全量 JSON 自己做判断 | 排单个可疑容器 |
| 本审计器 | 规则化 + 评分 + 修复 | 常规体检 / 教学基线 |
| trivy 直跑 | 官方全量漏洞数据 | 只要 CVE 报告 |

## Quick Start

前置：Docker（OrbStack / Docker Desktop 均可）；trivy（`brew install
trivy`）；宿主机 Python 3（仅标准库）。

漏洞库默认走国内镜像源（南大 ghcr 代理 + AWS ECR），可用
`TRIVY_DB_REPOSITORY` 覆盖；首次下载约 1 分钟，此后扫描秒级。

```bash
cd network/28_container_audit
./container_audit.sh            # 起对照容器 → 双引擎审计 → 汇总（约 20 秒）
./container_audit.sh apply      # 只备镜像/漏洞库并起两个对照容器
./container_audit.sh observe    # 只跑三步审计（需先 apply）
./container_audit.sh clean      # 移除容器并清理产物（缓存在，重跑秒级）
```

默认运行的真实输出（节选）：

```text
... # 输出首行空行省略
=====> [apply] 检查 Docker / trivy → 备旧镜像与漏洞库 → 起「危险」与「加固」两容器
  ✅ trivy 0.74.0（漏洞库走国内镜像源，可经环境变量覆盖）
  ✅ 旧镜像就位：nginx:1.19（2021 年 EOL，含大量已知 HIGH+ CVE 的对照靶）
  ✅ 漏洞库已就绪（缓存于 ~/.cache/trivy；后续扫描秒级）
  ✅ 两容器已起：bad = privileged + host 网络 + 挂 docker.sock；good = 全加固（--cap-drop ALL / 只读 / 非 root）

=====> [observe] ① 危险容器：应检出「特权 / docker.sock / host 网络」三件套
[28] 容器审计 · hosec28-bad（镜像 alpine:3.19）
== 检出 6 项（CRITICAL 2 / HIGH 1 / MEDIUM 1 / LOW 2） ==
  [CRITICAL] 特权模式（--privileged）：获得全部 capabilities + 宿主设备访问 + AppArmor 豁免，容器逃逸等同拿到宿主 root
    修复：去掉 --privileged；确需某项能力时用 --cap-add 最小化授予
  [CRITICAL] 挂载 Docker 套接字（可写）：容器内 /var/run/docker.sock 直通宿主 Docker 守护进程：可起特权容器/挂宿主任意目录 = 宿主 root
    修复：不要挂套接字；需要构建能力时改用 rootless BuildKit 或受控代理
  [HIGH] host 网络模式：共享宿主网络栈：容器可监听/嗅探宿主所有接口，绕过网络隔离
    修复：改回默认 bridge 或自定义网络，用 -p 只发布需要的端口
  [MEDIUM] 以 root 用户运行：应用被攻破即容器内 root；叠加特权/挂载配置将放大为宿主级风险
    修复：镜像声明 USER 非 root（或运行时 --user uid:gid）
  [LOW] 未启用 no-new-privileges：容器内 SUID 文件/可执行提权路径不会被内核拦截放大
    修复：加 --security-opt no-new-privileges（多数场景零成本）
  [LOW] 根文件系统可写：被入侵可持久化落盘；损坏后无法快速重建
    修复：加 --read-only，把需要写的目录用 tmpfs/卷单独挂载
评分 116 → 高危：存在等于宿主级权限的配置，建议立即整改
  ✓ 验收三件套全检出（privileged / docker-sock / host-network）；CRITICAL 2 项、评分 116 → 高危
  ✅ 每条检出都带「为什么危险 + 修复动作」（完整报告：artifacts/bad.md）

=====> [observe] ② 加固对照：同款审计器对全加固容器应零检出（准入线）
[28] 容器审计 · hosec28-good（镜像 alpine:3.19）
== 检出 0 项（无） ==
评分 0 → 通过基线：未发现危险配置
  ✓ 检出 0 项、评分 0 → 通过基线：未发现危险配置
  ✅ 加固基线容器 0 告警——审计器先证明不误报，再谈抓危险

=====> [observe] ③ 旧镜像 CVE：trivy 扫 HIGH/CRITICAL 并汇总（验收 ≥1）
[28] 镜像审计 · nginx:1.19（trivy HIGH/CRITICAL）
== HIGH+ 漏洞：CRITICAL 42 / HIGH 147（共 189） ==
  [CRITICAL] CVE-2018-25009 libwebp6 0.6.1-2 → 0.6.1-2+deb10u1
  [CRITICAL] CVE-2018-25010 libwebp6 0.6.1-2 → 0.6.1-2+deb10u1
  [CRITICAL] CVE-2018-25011 libwebp6 0.6.1-2 → 0.6.1-2+deb10u1
  [CRITICAL] CVE-2018-25012 libwebp6 0.6.1-2 → 0.6.1-2+deb10u1
  [CRITICAL] CVE-2018-25013 libwebp6 0.6.1-2 → 0.6.1-2+deb10u1
  [CRITICAL] CVE-2018-25014 libwebp6 0.6.1-2 → 0.6.1-2+deb10u1
  [CRITICAL] CVE-2019-8457 libdb5.3 5.3.28+dfsg1-0.5 → 暂无
  [CRITICAL] CVE-2020-36328 libwebp6 0.6.1-2 → 0.6.1-2+deb10u1
结论：检出 ≥1 个 HIGH+ → 升级基础镜像并重建（详见报告整改建议）
  ✓ 汇总 HIGH+ 189 个（CRITICAL 42 / HIGH 147），TOP 清单 8 条
  ✅ trivy 结果已汇总进报告与整改建议（完整报告：artifacts/cve.md）

=====> [clean] 移除两容器并清理产物（镜像与漏洞库缓存保留，重跑秒级）
  ✅ 容器与产物已清；nginx:1.19 与 trivy 漏洞库缓存保留
```

诚实预期（新手第一个失败点）：① CVE 数字随库更新漂移——看趋势与清零
动作，不背绝对值；② 漏洞库首次必须下载，还要过 Java DB（给 Java 依赖
单独维护的第二个库）一关，超时先换镜像源再怀疑挂死；③ 两台引擎互补：
配置全合规也可能背着 189 个 CVE，镜像干净也可能配置成宿主 root。

## How It Works

![配置 × CVE 双引擎：一本容器审计报告](images/container_audit.svg)

> 怎么看：上排配置引擎——危险容器经 docker inspect 解析、9 条规则判定，
> 检出 6 项（评分 116）；下排 CVE 引擎——旧镜像经 trivy 比对漏洞库，
> 汇总 189 个 HIGH+；两路结论汇入同一本审计报告（含修复与加固建议）。

> 🌐 **交互版**：本地打开 [`images/container_audit.html`](images/container_audit.html)。

**9 条规则在读什么**：全来自 inspect 字段——`Privileged`、`Mounts[]`
`.Source`（sock 与敏感目录）、`NetworkMode` / `PidMode`、`CapAdd`、
`User`、`SecurityOpt`、`ReadonlyRootfs`。

每条规则带「为什么危险 + 怎么修」——审计输出即整改单，修一条是一分。

输出里还会遇到四个工具词：capabilities（把 root 权限拆成一粒粒能力位的
机制）、AppArmor（限制程序能碰什么的强制访问控制模块）、tmpfs（内存里
的临时文件系统，写入不落盘）、rootless BuildKit（不依赖 Docker 守护
进程也能构建镜像的构建器）。

**trivy 在算什么**：把镜像每层的软件包（含版本）与漏洞库逐一对账——
它回答「这批货有多少已知坏件」，不回答「能不能被利用」。EOL 镜像的
正解不是逐个打补丁，而是换基础镜像重建。

**为什么盯着「等于宿主 root」**：容器逃逸的后果分级里，privileged /
docker.sock / host 网络-PID 是唯一能一步跨到宿主的组合；其余（root
用户、可写根、缺 no-new-privileges）是放大风险的「次级项」——评分表
把这条工程直觉固化成了权重。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **漏洞库下载超时**：默认 `mirror.gcr.io` 在国内不通——改用南大 ghcr
  代理（`ghcr.nju.edu.cn`）；Java DB 连代理也不收，转 AWS ECR 公共库。
- **首次扫描疑似卡死**：其实在下 Java DB（必须有，跳过会被拒绝）；
  之后缓存 3 天，扫描回到秒级。
- **bash 3.2 吞变量**：`$VAR（` 紧跟全角括号时，旧 bash 会把括号字节
  算进变量名报 unbound——加花括号 `${VAR}` 即解（开发时实踩）。
- **把 CVE 数当 KPI**：不同漏洞库版本数值不同——用来定位「要不要升
  镜像」，不用来对比「谁更安全」。

深入问答：

- **Q: 为什么 privileged 单独一条就判 CRITICAL？** A: 它一次性给全
  能力 + 设备 + 豁免，等于把容器做成宿主上的一台裸机——不需要组合拳。
- **Q: 189 个 CVE 怎么办？** A: 不逐个修——升级基础镜像到受支持版本
  重建，再用同一审计器回归；CI 卡口防止新的 EOL 镜像进来。
- **Q: 加固容器为什么要 0 告警？** A: 与 23 / 26 / 27 同一纪律：检测
  器先证明不误报（准入线），它的「高危」判断才值得信任。

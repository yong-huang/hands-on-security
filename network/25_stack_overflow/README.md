# 25 · Linux 栈溢出与 ret2win：让程序替我们读 flag

> 前二十四课都在「看」程序；这一课第一次「指挥」程序跑。靶子是容器里
> 一个用 gets（无边界读入的标准库函数）写的 C 程序：缓冲区 64 字节，
> 旁边蹲着一个从不被调用的 win()（后门函数：里面只有一句读 flag）。
> 三幕：① 用 cyclic（每 8 字节片段唯一的测长模式串）喂崩程序，gdb
> （调试器）读回寄存器 x30，量出返回地址偏移 72；② 72 字节填充 +
> p64(win) 覆写返回地址——ret2win（把返回地址改成现成的后门函数），
> flag 到手；③ 同一发 payload 打 canary（栈哨兵：入口写的随机 8 字节、
> 返回前核对）加固版——被 *** stack smashing detected *** 拦下。脚本
> 宿主跑 pwntools（Python 漏洞利用框架），容器用 socat（把程序 I/O
> 接成 TCP 服务）挂 9025 端口。

## Background

前二十四课读二进制是「站着看」；栈溢出是第一个「动手改」的漏洞类——
数据写超缓冲区边界，把栈上保存的控制信息当数据冲掉。1988 年 Morris
蠕虫（互联网第一只蠕虫）靠的就是它，如今它仍是 CTF（Capture The
Flag：解题与攻防对抗的竞赛）里 pwn（二进制利用方向）题的第一课。

本实验把这条链拆成三层：**缓冲区与它的邻座**（栈帧布局）、**精确制导**
（用 cyclic 量偏移，不靠猜）、**防护与反制**（canary 在跳转前掐断这条链）。

## What

一句话定义：**栈溢出利用 = 用「数据」冒充「地址」**——返回地址本是函数
「回去的坐标」，溢出把它改写成我们挑的坐标。

心智模型：栈帧像一摞自下而上的便签——函数进来先压好「上一摞在哪」
（帧指针 x29）与「从哪回来」（返回地址 x30），缓冲区是垫在最上面的一沓
空白便签；溢出就是从空白处一路写到那张「回来」的便签上。

失效边界：本实验有三条简化——`-no-pie`（地址固定）、不顾及 ASLR（装载
地址随机化）、无 canary。真实目标三条全开：地址随机、栈上多哨兵——
思路不变，但要先泄露信息再绕。

| 防护 | 拦住什么 | 本实验的处理 |
|:---|:---|:---|
| canary | 覆写返回地址（返回前核对随机哨兵） | 加固版对照：被拦（验收 ③） |
| NX | 在栈上执行 shellcode（注入的机器码） | -z execstack 关掉；ret2win 不靠它 |
| PIE | 代码地址随机化（打哪儿不确定） | -no-pie 白捡固定 win()；真目标要先泄露 |

## When to Use

典型场景：CTF pwn 的第一题（ret2win 相当于 Hello World）；把「缓冲区
溢出」从教材名词变成亲手打通的机理；为崩溃分析建立栈帧直觉。

何时不用：打真实现代系统——PIE + ASLR + canary + RELRO（装载后把关键
表锁成只读，防改表劫持）全家桶齐开，还得先做信息泄露、再串 ROP
（Return-Oriented Programming：把现成代码片段串成利用链）。

反过来它也是防御课：gets/strcpy 为什么被淘汰，亲手打一遍就懂；本实验
靶场仅限本机容器。

| 做法 | 机制 | 什么时候选它 |
|:---|:---|:---|
| pwntools（本节利用脚本） | 连接 + payload 组装一条龙 | 常规 CTF / 研究脚本 |
| 手写 socket + struct | 自己连、自己拼字节 | 想看清每一步 / 环境受限 |
| gdb 手工算 | 阅读崩溃现场 | 定偏移、验假设（本节用它量 72） |

## Quick Start

前置：Docker（首次构建 ubuntu + gcc + gdb + socat 镜像，约 1–2 分钟）；
宿主 Python3 + pwntools（`pip3 install pwntools`，装依赖走网络一次）。

```bash
cd network/25_stack_overflow
./stack_lab.sh            # 编译双版本 → 起靶场 → 定位偏移 → ret2win → canary 对照（约 15 秒）
./stack_lab.sh apply      # 只构建镜像 + 编译 + 起 9025/9026 两个 TCP 服务
./stack_lab.sh observe    # 只跑三步验证（需先 apply）
./stack_lab.sh clean      # 只清容器与 artifacts（镜像保留）
```

默认运行的真实输出（节选）：

```text
... # 输出首行空行省略
=====> [apply] 检查 Docker 与 pwntools → 构建靶场镜像 → 编译漏洞版 / canary 加固版
  ✅ 靶场镜像已构建（ubuntu 22.04 + gcc/glibc + gdb + socat）
  ↳ 链接器警告：the `gets' function is dangerous and should not be used. —— 漏洞本体
  ↳ readelf 符号表：调用 __stack_chk_fail 的引用数 —— vuln=0，vuln-canary=1
防护体检（pwntools 读 ELF 属性；NX 看 PT_GNU_STACK 段）：
  artifacts/vuln          canary=False  nx=False  pie=False  relro=Partial
  artifacts/vuln-canary   canary=True   nx=True   pie=False  relro=Partial
  ✅ 两个 TCP 服务已就绪：9025 = 漏洞版（-fno-stack-protector），9026 = canary 加固版

=====> [observe] ① cyclic 定位偏移：喂 200 字节 pattern，读崩溃现场的 x30（返回地址）
cyclic(200) 已写入 artifacts/cyclic.txt
  头部 aaaabaaa … 尾部 xaabyaab（每 8 字节片段全文件唯一）
  ↳ input:
  ↳ bye
  ↳ Program received signal SIGBUS, Bus error.
  ↳ x30            0x6161617461616173  7016996846897815923
崩溃现场 x30 = 0x6161617461616173（pattern 片段，说明返回地址被这批字节覆盖）
偏移 = 72
  ✅ 偏移 72 = 64 字节缓冲区 + 8 字节帧指针：第 73 字节起就是返回地址

=====> [observe] ② ret2win：填充 72 字节 + win() 地址 → 让靶子亲手读出 flag
目标 artifacts/vuln：win() = 0x400744（-no-pie 下地址固定，白捡的靶点）
payload = 72 字节填充 + p64(win)，共 80 字节
靶场回复：
    bye
    HOSEC25{r3t2w1n_0wns_th3_st4ck}
拿到 flag：HOSEC25{r3t2w1n_0wns_th3_st4ck}
  ✅ 返回地址被改写为 win()：控制流没走 main 的出口，而是替我们读了 /flag

=====> [observe] ③ canary 对照：同一套 payload 打 -fstack-protector-all 加固版
目标 artifacts/vuln-canary：win() = 0x400804（-no-pie 下地址固定，白捡的靶点）
payload = 72 字节填充 + p64(win)，共 80 字节
靶场回复：
    bye
    *** stack smashing detected ***: terminated
未拿到 flag——覆写被挡在函数返回之前
  ✅ canary 在函数返回前校验被改写 → *** stack smashing detected ***，控制流到不了 win()
  ↳ 为什么挡住：canary 是每次启动随机生成的 8 字节「哨兵」，压在缓冲区与返回地址之间；
    溢出必须逐字节穿过它——能精确定位偏移，就等于必然踩中它。

=====> [clean] 删除靶场容器并清理产物（镜像保留，重跑秒级）
  ✅ 容器与产物已清；靶场镜像 hosec25-lab 保留
```

诚实预期（新手第一个失败点）：① 偏移 72 是 cyclic **量出来的**，不是
背的——换个编译器或优化级别它就可能变；② canary 版只差返回前多一次
核对——防护加在收尾处；③ 本机 arm64 的寄存器叫 x29/x30 而非 rbp/ret，
但「缓冲区 → 帧指针 → 返回地址」三层结构同构。

## How It Works

![覆写返回地址：从 pattern 到 flag 的利用链](images/stack_overflow.svg)

> 怎么看：上排主链从靶场源码走到 ret2win 得手——双编译 → cyclic 定位
> 偏移 72 → 覆写返回地址 → 劫持 x30；下排是同一发 payload 打 canary 版
> 被哨兵拦下：成败两个出口并列对照。交互版图下方还有三张卡片：栈帧
> 布局、canary 原理与「为什么赢得轻松」。

> 🌐 **交互版**：本地打开 [`images/stack_overflow.html`](images/stack_overflow.html)。

**栈帧长什么样**：vuln() 进来时，buf[64] 在最上头，紧挨着压着帧指针
x29（8 字节，指回上一摞便签）与返回地址 x30（8 字节，回去的坐标）。
gets 从 buf 这头写起——72 字节刚好铺满 buf + x29，第 73 字节起写的就是
x30。

**ret 为什么听话**：函数收尾是固定动作——从栈里恢复 x29/x30 → ret（跳
去 x30）。我们写进去的 8 字节被当成「回去的坐标」，控制流就跟着走进了
win()。

**canary 凭什么挡得住**：加 -fstack-protector-all 后，函数入口在 buf 与
x29 之间塞进 8 字节随机哨兵（每次启动不同），返回前核对——想写到返回
地址就必然踩中它。

命中之后：__stack_chk_fail → glibc 打出 *** stack smashing detected ***
并终止，拦截点在「跳转之前」。

**为什么赢得轻松**：-no-pie 让 win() 固定在 0x400744（真实目标要先泄露
地址）；也没写 shellcode——NX 开着照打，因为改的是返回地址而非栈上
代码。

补丁：win() 末尾加 exit(0)——被劫持跳进来的函数，自身的返回地址栈
已不可信。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **接收端卡死、流量暴涨**：`recvall` 等不到静默期——没补 exit(0) 时
  win() 返回自己，无限循环刷 flag（开发时实测流量 8 MB）。
- **canary 版崩得悄无声息**：musl（alpine 的 C 库）命中 canary 是静默
  信号退出，没有提示文案——本实验特意选 ubuntu/glibc 才有教科书级的
  smashing 提示。
- **装 pwntools 现场编译爆炸**：旧版依赖 unicorn 在 Apple Silicon 没
  wheel 就源码编译。先 `pip3 install -U unicorn`（2.x 有 arm64 wheel）
  再装 pwntools。
- **被信号名带偏**：aarch64 上跳到非法地址常报 SIGBUS 而非 SIGSEGV——
  看寄存器里的 pattern 值，不要纠结信号名。

深入问答：

- **Q: 没有源码还能打吗？** A: 能——win() 的地址可以从符号表读，被
  stripped（剥掉符号）就从反汇编里找；本节带源码是为了看清每一层。
- **Q: 偏移 72 换个编译器还是 72 吗？** A: 不一定——优化与对齐都可能
  挪它；所以用 cyclic 量、不背数字，这是本节最值钱的动作。
- **Q: canary 开着怎么继续？** A: 先泄露哨兵值再原样写回（如格式化
  字符串漏洞），然后才轮到返回地址；或改用 canary 管不到的别的指针。

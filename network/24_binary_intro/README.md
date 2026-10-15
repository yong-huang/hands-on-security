# 24 · 二进制静态分析入门：手拆 ELF、readelf 对账与 crackme 通关

> 二进制是「没上锁的图纸」：入口地址、节表、字符串全在文件里写明。本
> 实验用纯 struct.unpack（Python 标准库：按格式串把字节拆成字段）手写
> ELF（Linux 可执行文件格式）/ Mach-O（macOS 可执行文件格式）解析器
> ——一个字节都不借 readelf（看 ELF 头的命令行工具）——对自编 C crackme
> （专门给人练破解的小程序）完成：头七字段与 readelf 逐字对账（7/7）；
> 口令与成功串定位到虚拟地址，并经 strings（扫可打印串）/ objdump（反
> 汇编与节转储）/ 实际运行三重验证；同一份源码的 Mach-O 产物再与 otool
> （macOS 的同类工具）对照。

## Background

前二十几课都在「连上去、发请求、读日志」；从这节课开始看**编译后的
世界**：拿到一个陌生的可执行文件，不运行它就能知道它是什么、给谁跑、
里面藏了什么字符串——这是逆向、恶意样本分析（静态分析 = 不执行、只读
文件字节）与 CTF（Capture The Flag：解题与攻防对抗的竞赛）的基本功。

工具（readelf/objdump/strings）人人会用，但把它们当黑盒，十年也说不清
一个字段从哪来——所以本实验先把解析器手写一遍，再拿工具对账。

## What

一句话定义：**静态分析 = 不执行、只读文件字节**，靠格式规范把人眼
看不懂的二进制还原成字段。

心智模型：看建筑图纸而不是走进去——承重墙（头字段：magic、entry、
machine）、房间号（节表：每段字节放哪、装到哪）、贴纸（字符串）。

失效边界：静态只能看「文件里写着什么」——加壳（重新打包改写内容）/加密
的样本没有明文结构（转实验 26 动态）；字符串看得见 ≠ 逻辑看得懂（要
反汇编）。

| 对账工具 | 管什么 | 本实验对什么 |
|:---|:---|:---|
| readelf -h | ELF 头字段（权威） | 7 字段逐字 |
| objdump -s | 节内「地址-字节」表 | 0x400818 的字节 |
| strings -t x | 可打印串 + 文件偏移 | 偏移口径 |
| otool -hv | Mach-O 头（macOS） | 四字段 |

## When to Use

典型场景：样本初筛（先 file/strings 再看要不要动）；CTF 逆向题的第一
小时；漏洞研究里定位常量与字符串地址。

何时不用：加壳样本先脱壳（解掉外层封装）再静态；符号表被剥离
（stripped：函数名、变量名等符号信息被去掉）+ 高度优化的大型程序，
纯手工静态性价比极低——上 Ghidra 这类反编译框架，手写解析器练的是
「地图感」。

| 做法 | 机制 | 什么时候选它 |
|:---|:---|:---|
| file + strings 三板斧 | 格式识别 + 线索 | 任何样本的第一步 |
| 手写解析器（本实验） | struct.unpack 逐字段 | 学结构、理解工具输出 |
| Ghidra / IDA | 反汇编 + 反编译 | 要读懂逻辑时 |

## Quick Start

前置：Docker（首次构建 alpine + gcc + binutils 的编译容器）；宿主机
clang（macOS 自带编译器，Xcode CLT）。首次约 1–2 分钟，之后 10 秒。

```bash
cd network/24_binary_intro
./binary_lab.sh            # 编译双格式 → 拆解对账 → 字符串寻址（约 10 秒）
./binary_lab.sh apply      # 只编译 ELF（容器）与 Mach-O（宿主）并抓对照材料
./binary_lab.sh observe    # 只跑三步对账
./binary_lab.sh clean      # 只清 artifacts（编译镜像保留）
```

默认运行的真实输出（节选）：

```text
... # 输出首行空行省略
=====> [apply] 构建编译容器 → 产 ELF（容器内交叉）与 Mach-O（宿主 clang）+ 对照材料
  ✅ ELF crackme 已编译：ELF 64-bit LSB executable, ARM aarch64
  ✅ Mach-O 对照件已编译（同一份源码，宿主 clang）——两种格式同源

=====> [observe] ① 手写解析器 vs readelf -h：七个字段逐一对账
[elf] Magic   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
[elf] Class   ELF64
[elf] Data    2's complement, little endian
[elf] OS/ABI  UNIX - System V
[elf] Type    EXEC
[elf] Machine AArch64
[elf] Entry   0x400610
  Magic   自研=7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  readelf=7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class   自研=ELF64  readelf=ELF64
  Data    自研=2's complement, little endian  readelf=2's complement, little endian
  OS/ABI  自研=UNIX - System V  readelf=UNIX - System V
  Type    自研=EXEC  readelf=EXEC
  Machine 自研=AArch64  readelf=AArch64
  Entry   自研=0x400610  readelf=0x400610
  ✅ 7/7 字段逐字一致（magic/class/data/osabi/type/machine/entry，验收 ①）

=====> [observe] ② 关键字符串寻址：strings 偏移 → 节表映射 → 虚拟地址（objdump 独立复核）
[find] "ACCESS GRANTED! flag=HOSEC24-STATIC-OK" 文件偏移 0x818（strings -t x 同口径） → 节 .rodata → 虚拟地址 0x400818
[find] "hosec24-gate-key" 文件偏移 0x800（strings -t x 同口径） → 节 .rodata → 虚拟地址 0x400800
  ✓ strings 偏移一致（0x818）
  ✓ objdump .rodata 在 0x400818 的字节与字符串逐字吻合（独立复核）
  ↳ 行为验证：ACCESS GRANTED! flag=HOSEC24-STATIC-OK
  ✅ 成功串定位并双重复核；同句口令也是明文——静态直接拿走（验收 ②）

=====> [observe] ③ Mach-O 头对照：同一份源码，宿主 clang 产物 vs otool -hv
[macho] Magic     0xfeedfacf（Mach-O 64 位）
[macho] CPUType   16777228 (ARM64)
[macho] FileType  2 (EXECUTE)
[macho] NCmds     18
  otool：magic=MH_MAGIC_64 cpu=ARM64 filetype=EXECUTE ncmds=18
  ✅ Mach-O 四字段与 otool 一致——ELF 与 Mach-O 同源不同形
... # clean 段省略
```

诚实预期（新手第一个失败点）：① 手写不等于弃用工具——是把工具当
**对账对象**（7/7 字段、字节级复核）；② strings 给的是**文件偏移**，
直接当地址用会差一个节基址：0x818（文件）→ 0x400818（虚拟）；③ ELF
在容器里产、Mach-O 在宿主产——同源码不同形，别找错文件。

## How It Works

![手拆 ELF 的解析流水线](images/binary_intro.svg)

> 怎么看：左边两个二进制（ELF + Mach-O）进流水线：认魔数 → 拆头字段 →
> 读节表 → 字符串寻址；最右把结论交给三个独立工具逐字段对账。

> 🌐 **交互版**：本地打开 [`images/binary_intro.html`](images/binary_intro.html)。

**头拆解的读法**：前 16 字节是 ident——`7f 45 4c 46` 是魔数（magic，
文件开头的身份字节），第 5 字节 class（2=64 位）、第 6 字节 endian
（1=小端）先定「怎么拆」；其后固定布局：entry@0x18、machine@0x12——
对账的 7 个字段就从此拆出。

**节表就是那座桥**：可以把节表想成连通「文件偏移」与「虚拟地址」的
桥——shoff 指向节表数组，每项记录一段字节的 `addr`（装载后的虚拟地址）
与 `offset`（文件位置）。桥的公式：**VA = sh_addr + (off − sh_offset)**。

失效边界：桥只覆盖节表登记的字节——不在任何节内的字节没有可查的地址；
本例 .rodata 0x400800/0x800：文件 0x818 → 虚拟 0x400818。

**三重独立复核**：strings 对偏移、objdump -s 对字节（在 0x400818 处
逐字吻合）、真跑一遍对行为（容器里用找到的口令跑出 GRANTED）——静态
结论必须能被独立证据收口，这是本节最先要立的习惯。

**Mach-O 同源不同形**：头部字段更少，且没有节表——用 load commands
（加载命令：头部里描述分段与链接信息的指令列表）描述分段；对照停在
头四个字段。理解任何格式的通用方法都是三步：读魔数 → 读头部 → 找表。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **把 strings 偏移当地址**：0x818 是文件位置、0x400818 是虚拟地址——
  差的一个节基址要靠节表映射出来。
- **工具输出解析崩了**：binutils 输出格式随版本微调——对账按「字段」
  解析（split 冒号），别按固定列位。
- **拿 /bin/ls 做 Mach-O 对照**：Apple Silicon 的系统件是 fat（多架构
  打包），magic 是 0xcafebabe——对照用自编的 thin 文件。
- **地址对不上预期**：默认 PIE（位置无关可执行，装载时随机基址）下
  这些地址都带装载偏移——教学用 `-no-pie` 固定地址。

深入问答：

- **Q: 为什么不用 pyelftools？** A: 用，但先手写——知道每个字段在哪，
  才看得懂工具输出；本实验的解析器就是「教学版 pyelftools」。
- **Q: 字符串能改吗？** A: 能——找到偏移直接改字节（等长补丁）；
  改长度就要重排节表，那是更深一层的练习。
- **Q: 拿到陌生样本的第一步？** A: file 认格式 → strings 看线索 →
  头/节表定结构 → 决定是否上反汇编或沙箱；本实验就是这条链的手工版。

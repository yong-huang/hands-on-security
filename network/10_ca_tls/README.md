# 10 · 自建 CA 与 TLS 全流程：X.509 证书链、SAN 与三种信任场景

> HTTPS 地址栏的锁图标背后是一条证书链：根 CA（证书颁发机构）给服务器
> 证书背书，客户端逐级验签直到命中本地信任锚。本实验用 openssl 自建根 CA、
> 签发带 SAN 的服务器证书，起 https://localhost:8443，再用 curl 与 Python
> 客户端跑三种信任场景——通过、被拒、被拒。全部证书只在本机实验使用。

## Background

实验 06 演示过明文 HTTP 的代价：同网段任何人都能读出登录口令。TLS 把
这条通道封起来，同时解决两件事：保密（谁也看不懂）与身份（对面真的是
「它声称的那个服务」）。

保密靠握手协商的会话密钥（正是实验 09 的混合加密）；身份靠 PKI——
公钥基础设施（Public Key Infrastructure）：一套由 CA 签发、客户端逐级
验证的身份体系。服务器出示证书（X.509 格式：公钥＋身份声明＋签发者
签名），而 CA 自己由操作系统预装的「根证书」背书——那叫信任锚。

## What

一句话定义：证书链校验是**客户端沿着「服务器证书 → 中间 CA → 根 CA」
逐级验签、直到命中本地信任锚的判定过程**。

心智模型：护照与签发国——海关（客户端）不直接信你的护照（证书），它信
「签发国」（CA）的背书体系，手里有一份「承认的国家名单」（信任锚）。
失效边界：名单里没有签发国，或国徽对不上（另一套 CA 签的），体系当场
失灵——与证书做得漂不漂亮无关。

一张证书真正的三个校验点：

| 要素 | 内容 | 本实验体现 |
|:---|:---|:---|
| 签名链 | 每级用上一级私钥签名 | `openssl verify` 返回 OK |
| SAN（Subject Alternative Name，主体备用名） | 证书声明适配哪些域名/IP | localhost / 127.0.0.1 |
| 用途与有效期 | serverAuth、过期时间 | 365 天、`extendedKeyUsage` |

## When to Use

典型场景：给内网服务上 HTTPS（自建 CA + 每台设备安装根证书）；排查
「证书错误」类故障（看懂 `unable to get local issuer certificate`）；
理解企业 MDM（Mobile Device Management，终端设备管理）、抓包代理为什么
都靠「装根证书」工作。

何时不用：公网服务别用自建 CA——公众不会安装你的根，请用 Let's Encrypt
或商业 CA；调试时不要随手关校验（`verify=False` 相当于把锁拆了再贴上
「已上锁」的标签）。

| 方案 | 机制 | 什么时候选它 |
|:---|:---|:---|
| 自建 CA（本实验） | 自己当根，设备预装 | 内网、实验、抓包代理 |
| Let's Encrypt | 免费、自动化签发 | 公网服务的事实标准 |
| 商业 CA | 付费、O 字段背书 | 电商等需要机构身份的场景 |

## Quick Start

前置：OpenSSL 3（脚本优先用 Homebrew 的 openssl@3；系统自带 LibreSSL 会被
检测拒绝并提示安装）；python3 标准库自带 ssl 与 http.server，无需装包。

```bash
cd network/10_ca_tls
./tls_lab.sh              # 造证书 → 起服务 → 三场景校验 → 清理（约 4 秒）
./tls_lab.sh apply        # 只生成证书链并起服务
./tls_lab.sh observe      # 只跑校验三场景
./tls_lab.sh clean        # 停服务、清证书
```

默认运行（apply → observe → clean）的真实输出（节选）：

```text
... # 块首空行与 [apply] 段头省略
  ℹ️  openssl：/opt/homebrew/opt/openssl@3/bin/openssl（OpenSSL 3.6.3）
  ✅ 根 CA（hosec-lab-ca）、服务器证书（SAN: localhost/127.0.0.1）、对照 CA 就绪
  ✅ HTTPS 服务就绪：https://localhost:8443（证书：artifacts/ca/server.crt）
... # 「场景一」段头省略
hello over TLS: certificate verified by hosec lab CA
  ✅ 校验通过并取回内容（HTTP 200）
... # 「场景二」段头省略
  curl: (60) SSL certificate problem: unable to get local issuer certificate
... # curl 错误块的附加说明行省略
  ✅ 按预期被拒（错误信息见上：证书链不成立于系统信任库）
... # 「场景三」整段与 verify 段头省略
artifacts/ca/server.crt: OK
[CLIENT] 信任源：artifacts/ca/ca.crt
  ✅ 握手成功：TLSv1.3 / TLS_AES_256_GCM_SHA384
     对端证书 CN=localhost SAN=(('DNS', 'localhost'), ('IP Address', '127.0.0.1'))
... # 响应行、两段预期失败输出与其 ✅ 结论、clean 段省略
```

诚实预期（新手第一个失败点）：场景二、三报错是预期结果——校验失败就该
拒绝。`clean` 会删光证书，想手动 curl 请先 `apply`。

## How It Works

![证书链的一生](images/tls_lab.svg)

> 怎么看：左上角根 CA 用私钥给签发盖章，服务器证书（带 SAN）装载到
> HTTPS 服务；客户端在握手中拿到整条链，逐级验证直到信任锚——命中则
> 建立连接，对不上就断。

> 🌐 **交互版**：本地打开 [`images/tls_lab.html`](images/tls_lab.html)。

**四条 openssl 命令就是全部仪式**：自签根 CA（无上级签发者、自己给自己
签，`req -x509`）→ 服务器生成密钥与 CSR（证书签名请求：公钥与身份）→
CA 签发（`x509 -req` 用 CA 私钥盖章）→ 一套对照 CA。配置里 `v3_server`
段的 SAN 决定它适配谁。

**握手时校验发生在哪**：客户端收到链后，在 TLS 握手内完成验签、SAN 比对、
有效期与用途检查；通过才继续协商会话密钥。客户端输出里的
`TLSv1.3 / TLS_AES_256_GCM_SHA384` 就是校验通过后协商的结果；
`getpeercert()` 拿到的 SAN 正是被校验过的字段。

**为什么 CN 不再作数**：早年用 CN（Common Name，通用名）声明域名，但一张
证书只能写一个名字、与现代多域名场景冲突；RFC 2818（IETF 的 HTTPS 规范，
2000 年）起客户端以 SAN 为准，主流实现索性忽略 CN。自签证书常缺 SAN，
浏览器因此连例外按钮都不给。

**场景二与场景三都报同一个错，区别在哪**：场景二里，客户端根本没配置
实验 CA（等价于没装根）；场景三里装了对照 CA，但签名链指向的是实验 CA。
两种情况下「找不到签发者」都是真实描述——信任锚要么没有、要么对不上
（链末端那张「叶子证书」并非自己签给自己——只是签发者不在信任库）。

## Pitfalls & Q&A

踩坑清单（现象 → 原因 → 解法）：

- **系统 LibreSSL 跑不了**：本实验要求 OpenSSL 3（保证证书主体名与校验
  行为一致）——脚本会自动检测并提示 `brew install openssl@3`。
- **缺 SAN 被浏览器拦**：给配置加 `subjectAltName`，别只写 CN。
- **`curl -s` 看不到错误**：`-s` 会连报错一起静默，调试用 `-sS`。
- **端口被占用**：`LAB_PORT=8444 ./tls_lab.sh` 换端口。

深入问答：

- **Q: 中间 CA 是干什么的？** A: 根私钥太珍贵，不直接签发服务器证书；
  中间 CA 用根签名、再由它签发——链条变长但根更安全（本实验为简化只用
  一级，`openssl verify` 同样适用于多级链）。
- **Q: 为什么抓包代理都要你「安装并信任」一个证书？** A: 它要成为你流量
  的中间人：用它自己的 CA 现签伪证书。装上根证书，链条就再次「同源」了
  ——这也是恶意软件常见的伎俩，所以系统对根证书安装极为敏感。
- **Q: mTLS 是什么？** A: 双向 TLS：服务器也校验客户端的证书（clientAuth
  用途）——服务间认证常用；本实验只做了单向（serverAuth）。
- **Q: 证书过期后连接会怎样？** A: 校验失败、连接被拒；生产环境靠自动
  续期（Let's Encrypt 默认 90 天）把过期变成不可能事件。

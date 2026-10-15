#!/usr/bin/env python3
# =============================================================================
# 28 · 容器安全审计器 —— docker inspect 危险配置 + trivy CVE 汇总 + 加固建议
#   容器模式: python3 audit.py container <名称> [--json out.json] [--report out.md]
#   镜像模式: python3 audit.py image <镜像>   [--json out.json] [--report out.md]
#   检查项（容器）: 特权模式 / docker.sock 挂载 / host 网络 / host PID /
#     危险 capabilities / root 运行 / 宿主敏感目录挂载 / 缺 no-new-privileges /
#     根文件系统可写——每条附严重级、解释与修复动作
#   CVE（镜像）: trivy 扫 HIGH/CRITICAL，汇总计数与 TOP 清单
# =============================================================================
import argparse
import json
import subprocess
import sys
from pathlib import Path

# 危险 capabilities：单项即接近全权，逐条给出理由
DANGEROUS_CAPS = {
    "SYS_ADMIN": "≈ 全权：mount/命名空间/内核接口都能碰",
    "SYS_PTRACE": "可注入其他进程（含宿主同 PID 视角）",
    "SYS_MODULE": "可加载内核模块 = 改内核",
    "NET_ADMIN": "可改网络配置/抓包/隧道",
    "DAC_READ_SEARCH": "绕过文件读权限检查",
    "SYS_RAWIO": "直接访问 I/O 端口",
}
SENSITIVE_HOST_DIRS = ("/", "/etc", "/root", "/home", "/var/lib/docker",
                       "/var/run", "/proc", "/sys", "/boot")
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def inspect_container(name):
    r = run(["docker", "inspect", name])
    if r.returncode != 0:
        sys.exit(f"docker inspect 失败：{r.stderr.strip()[:200]}")
    return json.loads(r.stdout)[0]


def audit_container(cfg):
    """返回 findings 列表：{check, severity, title, detail, fix}"""
    hc = cfg.get("HostConfig", {})
    conf = cfg.get("Config", {})
    f = []

    def add(check, sev, title, detail, fix):
        f.append({"check": check, "severity": sev, "title": title, "detail": detail, "fix": fix})

    if hc.get("Privileged"):
        add("privileged", "CRITICAL", "特权模式（--privileged）",
            "获得全部 capabilities + 宿主设备访问 + AppArmor 豁免，容器逃逸等同拿到宿主 root",
            "去掉 --privileged；确需某项能力时用 --cap-add 最小化授予")
    sock = [m for m in cfg.get("Mounts", []) if m.get("Source", "").endswith("/docker.sock")]
    if sock:
        rw = "（可写）" if sock[0].get("RW") else "（只读）"
        add("docker-sock", "CRITICAL", "挂载 Docker 套接字" + rw,
            f"容器内 {sock[0].get('Destination')} 直通宿主 Docker 守护进程：可起特权容器/挂宿主任意目录 = 宿主 root",
            "不要挂套接字；需要构建能力时改用 rootless BuildKit 或受控代理")
    if hc.get("NetworkMode") == "host":
        add("host-network", "HIGH", "host 网络模式",
            "共享宿主网络栈：容器可监听/嗅探宿主所有接口，绕过网络隔离",
            "改回默认 bridge 或自定义网络，用 -p 只发布需要的端口")
    if hc.get("PidMode") == "host":
        add("host-pid", "HIGH", "host PID 命名空间",
            "可见宿主全部进程，可向宿主进程发信号/读部分状态",
            "去掉 --pid=host；调试用 --pid=container:xxx 或 nsenter 临时进入")
    caps = sorted(set(hc.get("CapAdd") or []) & set(DANGEROUS_CAPS))
    if caps:
        detail = "；".join(f"{c}（{DANGEROUS_CAPS[c]}）" for c in caps)
        add("cap-add", "HIGH", "危险 capabilities", detail,
            "逐项移除；SYS_ADMIN 等没有安全用法，是逃逸常见起点")
    user = (conf.get("User") or "").strip()
    if user in ("", "0", "0:0", "root"):
        add("root-user", "MEDIUM", "以 root 用户运行",
            "应用被攻破即容器内 root；叠加特权/挂载配置将放大为宿主级风险",
            "镜像声明 USER 非 root（或运行时 --user uid:gid）")
    for m in cfg.get("Mounts", []):
        src = m.get("Source", "")
        if src.endswith("/docker.sock"):
            continue
        if src in SENSITIVE_HOST_DIRS or any(src.startswith(d + "/") for d in ("/etc", "/root", "/var/lib/docker")):
            add("sensitive-mount", "HIGH", f"挂载宿主敏感路径 {src}",
                f"→ {m.get('Destination')}{'（可写）' if m.get('RW') else ''}：容器内可直接读改宿主配置/数据",
                "只挂必要子目录，且尽量 :ro；避免把 /etc、/root 这类整目录带入容器")
            break
    opts = " ".join(hc.get("SecurityOpt") or [])
    if "no-new-privileges" not in opts:
        add("no-new-privileges", "LOW", "未启用 no-new-privileges",
            "容器内 SUID 文件/可执行提权路径不会被内核拦截放大",
            "加 --security-opt no-new-privileges（多数场景零成本）")
    if not hc.get("ReadonlyRootfs"):
        add("readonly-rootfs", "LOW", "根文件系统可写",
            "被入侵可持久化落盘；损坏后无法快速重建",
            "加 --read-only，把需要写的目录用 tmpfs/卷单独挂载")
    return f


def verdict(score, findings):
    if not findings:
        return "通过基线：未发现危险配置"
    if any(x["severity"] == "CRITICAL" for x in findings):
        return "高危：存在等于宿主级权限的配置，建议立即整改"
    if any(x["severity"] == "HIGH" for x in findings):
        return "中危：存在明显削弱隔离的配置"
    return "低危：建议按加固清单收敛"


def scan_image(ref):
    """trivy 扫 HIGH/CRITICAL，返回计数与 TOP 清单"""
    r = run(["trivy", "image", "--no-progress", "--skip-version-check",
             "--scanners", "vuln", "--severity", "HIGH,CRITICAL",
             "--format", "json", ref])
    if r.returncode != 0 or not r.stdout.strip():
        hint = "（检查网络/漏洞库镜像源；首次运行可先 trivy image --download-db-only）"
        sys.exit(f"trivy 扫描失败{hint}\n{r.stderr.strip()[-300:]}")
    data = json.loads(r.stdout)
    vulns = []
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            vulns.append(v)
    crit = [v for v in vulns if v["Severity"] == "CRITICAL"]
    high = [v for v in vulns if v["Severity"] == "HIGH"]
    crit.sort(key=lambda v: v["VulnerabilityID"])
    high.sort(key=lambda v: v["VulnerabilityID"])
    top = (crit + high)[:8]
    return {"critical": len(crit), "high": len(high), "total": len(vulns), "top": top}


def report_container_md(path, name, cfg, findings, score):
    hc, conf = cfg.get("HostConfig", {}), cfg.get("Config", {})
    lines = [
        f"# 容器审计报告 · {name}",
        "",
        "## 1. 概览",
        "",
        f"- 镜像：{conf.get('Image')}｜网络：{hc.get('NetworkMode')}｜特权：{bool(hc.get('Privileged'))}",
        f"- 检出：{len(findings)} 项（" + " / ".join(
            f"{s} {sum(1 for x in findings if x['severity'] == s)}" for s in SEVERITY_ORDER
            if any(x['severity'] == s for x in findings)) + "）" if findings else f"- 检出：0 项",
        f"- 评分：{score} → {verdict(score, findings)}",
        "",
        "## 2. 检出项与修复",
        "",
        "| 严重级 | 检查项 | 为什么危险 | 修复动作 |",
        "|:---|:---|:---|:---|",
    ]
    for x in sorted(findings, key=lambda y: SEVERITY_ORDER.index(y["severity"])):
        lines.append(f"| {x['severity']} | {x['title']} | {x['detail']} | {x['fix']} |")
    lines += ["", "## 3. 加固基线清单", "",
              "- `--cap-drop ALL` + 按需单项添加；永不 `--privileged`",
              "- 不挂 `docker.sock`；网络用默认 bridge + 精确 `-p`",
              "- 镜像声明非 root `USER`；`--read-only` + 必要目录卷",
              "- `--security-opt no-new-privileges`；定期用本审计器回归",
              ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def report_image_md(path, ref, res):
    lines = [
        f"# 镜像 CVE 报告 · {ref}",
        "",
        "## 1. 概览",
        "",
        f"- HIGH/CRITICAL：**CRITICAL {res['critical']} / HIGH {res['high']}**（共 {res['total']}）",
        f"- 结论：检出 ≥1 个 HIGH+ 漏洞，镜像不可作为当前基线直接投产",
        "",
        "## 2. TOP 漏洞（CRITICAL 优先）",
        "",
        "| 漏洞 | 包 | 当前版本 | 修复版本 |",
        "|:---|:---|:---|:---|",
    ]
    for v in res["top"]:
        lines.append(f"| {v['Severity']} {v['VulnerabilityID']} | {v.get('PkgName')} | "
                     f"{v.get('InstalledVersion')} | {v.get('FixedVersion') or '暂无'} |")
    lines += ["", "## 3. 整改建议", "",
              "- 升级基础镜像到受支持版本（nginx:1.19 已 EOL）并重建",
              "- CI 中加入 `trivy image --exit-code 1 --severity HIGH,CRITICAL` 卡口",
              "- 漏洞数随漏洞库更新变化——以审计当日库为准，关注趋势而非绝对值",
              ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main():
    p = argparse.ArgumentParser(description="28 · 容器安全审计器")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("container", help="审计容器危险配置")
    c.add_argument("name")
    c.add_argument("--json")
    c.add_argument("--report")
    i = sub.add_parser("image", help="审计镜像 HIGH+ CVE")
    i.add_argument("ref")
    i.add_argument("--json")
    i.add_argument("--report")
    args = p.parse_args()

    if args.cmd == "container":
        cfg = inspect_container(args.name)
        name = cfg.get("Name", args.name).lstrip("/")
        findings = audit_container(cfg)
        score = sum(SEVERITY_WEIGHT[x["severity"]] for x in findings)
        counts = {s: sum(1 for x in findings if x["severity"] == s) for s in SEVERITY_ORDER}
        brief = " / ".join(f"{s} {counts[s]}" for s in SEVERITY_ORDER if counts[s])
        print(f"[28] 容器审计 · {name}（镜像 {cfg.get('Config', {}).get('Image')}）")
        print(f"== 检出 {len(findings)} 项（{brief or '无'}） ==")
        for x in sorted(findings, key=lambda y: SEVERITY_ORDER.index(y["severity"])):
            print(f"  [{x['severity']}] {x['title']}：{x['detail']}")
            print(f"    修复：{x['fix']}")
        print(f"评分 {score} → {verdict(score, findings)}")
        if args.json:
            Path(args.json).write_text(json.dumps(
                {"container": name, "image": cfg.get("Config", {}).get("Image"),
                 "findings": findings, "score": score, "verdict": verdict(score, findings)},
                ensure_ascii=False, indent=1), encoding="utf-8")
        if args.report:
            report_container_md(args.report, name, cfg, findings, score)
        return 0
    else:
        res = scan_image(args.ref)
        print(f"[28] 镜像审计 · {args.ref}（trivy HIGH/CRITICAL）")
        print(f"== HIGH+ 漏洞：CRITICAL {res['critical']} / HIGH {res['high']}（共 {res['total']}） ==")
        for v in res["top"]:
            fixv = v.get("FixedVersion") or "暂无"
            print(f"  [{v['Severity']}] {v['VulnerabilityID']} {v.get('PkgName')} "
                  f"{v.get('InstalledVersion')} → {fixv}")
        print("结论：检出 ≥1 个 HIGH+ → 升级基础镜像并重建（详见报告整改建议）")
        if args.json:
            slim = [{k: v.get(k) for k in (
                "VulnerabilityID", "Severity", "PkgName", "InstalledVersion", "FixedVersion")}
                for v in res["top"]]
            Path(args.json).write_text(json.dumps(
                {"image": args.ref, "critical": res["critical"], "high": res["high"],
                 "total": res["total"], "top": slim}, ensure_ascii=False, indent=1), encoding="utf-8")
        if args.report:
            report_image_md(args.report, args.ref, res)
        return 0 if res["total"] >= 1 else 1


if __name__ == "__main__":
    sys.exit(main())

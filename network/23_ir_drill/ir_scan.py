#!/usr/bin/env python3
"""23 · Linux 入侵排查脚本（IR triage）—— 对「导出的文件系统」做只读取证

用法:
    python3 ir_scan.py scan --root artifacts/target-fs
                        [--report artifacts/ir-report.md] [--json artifacts/scan.json]

五路检查：计划任务 / 账号（UID 0 异常）/ SSH 授权键 / 隐藏 SUID / 命令历史。
每处命中计分并留证据（路径 + 片段 + mtime，UTC），--report 生成含
「证据路径 + 发现时间线」的 IR 报告。面向离线取证（docker export 快照等）。
"""
import argparse
import json
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

CRITICAL, HIGH, MEDIUM = 40, 25, 15
CRON_SUSPECT = re.compile(r"(/dev/tcp\b|nc\s+-e|bash\s+-i|curl\b|wget\b|base64\b)", re.I)
HIST_SUSPECT = re.compile(
    r"(/dev/tcp\b|nc\s+-e|bash\s+-i|curl\b|wget\b|base64\b|chmod\s+\+?s|useradd|/etc/passwd|/etc/shadow)",
    re.I)
SUID_ALLOW = {                            # 干净 ubuntu:22.04 基线的标准 SUID（实测清单）
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd", "/usr/bin/mount",
    "/usr/bin/newgrp", "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/umount",
}
FIX_HINTS = {
    "账号": "删除该账号与其 home 目录；复核 /etc/sudoers 与其他 UID 0 条目",
    "计划任务": "删除该 cron 文件；检查 /etc/crontab 与用户级 crontab",
    "SSH 授权键": "清空 authorized_keys 中的陌生公钥；轮换相关私钥",
    "SUID 后门": "去除 SUID 位（chmod u-s）并确认文件来源；比对安装包校验",
    "命令历史": "归档保存后清理；按历史逐条复核落地的文件与账号",
}


def mtime_utc(p: Path) -> str:
    return datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def finding(root: Path, cat, sev, score, path: Path, detail) -> dict:
    return {"category": cat, "severity": sev, "score": score,
            "path": "/" + str(path.relative_to(root)), "detail": detail,
            "mtime": mtime_utc(path)}


def check_cron(root: Path):
    out = []
    files = []
    for d in ("etc/cron.d", "var/spool/cron/crontabs"):
        if (root / d).is_dir():
            files += [p for p in sorted((root / d).iterdir()) if p.is_file()]
    if (root / "etc/crontab").is_file():
        files.append(root / "etc/crontab")
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and CRON_SUSPECT.search(line):
                out.append(finding(root, "计划任务", "高", HIGH, f, line[:120]))
                break                       # 每个文件报一次即可
    return out


def check_users(root: Path):
    out = []
    pw = root / "etc/passwd"
    if not pw.is_file():
        return out
    for line in pw.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[2] == "0" and parts[0] != "root":
            out.append(finding(root, "账号", "严重", CRITICAL, pw, line[:120]))
    return out


def check_ssh(root: Path):
    out = []
    homes = [root / "root"]
    if (root / "home").is_dir():
        homes += sorted(p for p in (root / "home").iterdir() if p.is_dir())
    for h in homes:
        ak = h / ".ssh" / "authorized_keys"
        if ak.is_file():
            keys = [l.strip() for l in ak.read_text(encoding="utf-8", errors="replace").splitlines()
                    if l.strip() and not l.startswith("#")]
            if keys:
                out.append(finding(root, "SSH 授权键", "高", HIGH, ak, keys[0][:96]))
    return out


def check_suid(root: Path):
    out = []
    for p in root.rglob("*"):
        try:
            st = p.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or not (st.st_mode & stat.S_ISUID):
            continue
        rel = "/" + str(p.relative_to(root))
        if rel in SUID_ALLOW:
            continue
        out.append(finding(root, "SUID 后门", "中", MEDIUM, p,
                           f"mode {oct(st.st_mode & 0o7777)}——非标准 SUID"))
    return out


def check_history(root: Path):
    out = []
    files = [root / "root" / ".bash_history"]
    if (root / "home").is_dir():
        files += [p / ".bash_history" for p in sorted((root / "home").iterdir()) if p.is_dir()]
    for f in files:
        if not f.is_file():
            continue
        bad = [l.strip() for l in f.read_text(encoding="utf-8", errors="replace").splitlines()
               if l.strip() and HIST_SUSPECT.search(l)]
        if bad:
            out.append(finding(root, "命令历史", "中", MEDIUM, f,
                               f"{len(bad)} 条可疑，如：{bad[0][:96]}"))
    return out


CHECKS = (check_cron, check_users, check_ssh, check_suid, check_history)


def verdict(score: int) -> str:
    if score == 0:
        return "未见异常"
    if score < 50:
        return "低度可疑"
    if score < 100:
        return "中度可疑"
    return "高度疑似失陷"


def scan(root: Path):
    findings = []
    for fn in CHECKS:
        findings += fn(root)
    findings.sort(key=lambda x: (-x["score"], x["path"]))
    return findings


def write_report(root: Path, findings, out: Path):
    score = sum(f["score"] for f in findings)
    ts = sorted(f["mtime"] for f in findings)
    lines = ["# 应急响应排查报告（自动生成）", "",
             f"> 排查对象：`{root}`（docker export 只读快照）· 时间线时区：UTC · 工具：ir_scan.py", "",
             "## 1. 结论摘要", ""]
    if findings:
        lines.append(f"共发现 **{len(findings)} 处异常**，累计评分 **{score}** → **{verdict(score)}**。")
        lines.append(f"最早痕迹 {ts[0]}（UTC），最晚 {ts[-1]}（UTC）。")
    else:
        lines.append("未发现异常——该快照可视为干净基线。")
    lines += ["", "## 2. 发现清单（含证据路径）", ""]
    for f in findings:
        lines += [f"### [{f['severity']}] {f['category']} · `{f['path']}`（{f['mtime']}）",
                  f"- 证据：`{f['detail']}`",
                  f"- 处置：{FIX_HINTS.get(f['category'], '人工复核')}", ""]
    lines += ["## 3. 发现时间线（按证据 mtime 还原，UTC）", "",
              "| 时间 | 类别 | 证据路径 |", "|:---|:---|:---|"]
    for f in sorted(findings, key=lambda x: x["mtime"]):
        lines.append(f"| {f['mtime']} | {f['category']} | {f['path']} |")
    lines += ["", "## 4. 处置建议（通用）", "",
              "- 先取证后动作：本实验用 docker export 得到只读快照，真实环境对应磁盘/内存镜像；",
              "- 清除五项后门：cron 文件、异常账号、authorized_keys、SUID 位、history 归档；",
              "- 根因与横向：全面改密（含口令复用机器）、排查入口暴露面、巡检同网段其他主机。"]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def cmd_scan(a):
    root = Path(a.root)
    if not root.is_dir():
        print(f"[!] 根目录不存在：{root}（先用 docker export 导出快照）", file=sys.stderr)
        return 1
    findings = scan(root)
    score = sum(f["score"] for f in findings)
    print(f"[IR] 只读取证：root = {root}")
    for f in findings:
        print(f"[{f['severity']} {f['score']}] {f['category']} · {f['path']}（{f['mtime']} UTC）")
        print(f"        └ {f['detail']}")
    print(f"[=] 共 {len(findings)} 处异常 / 评分 {score} → 结论：{verdict(score)}")
    if a.json:
        Path(a.json).write_text(json.dumps(
            {"root": str(root), "score": score, "verdict": verdict(score),
             "findings": findings}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if a.report:
        write_report(root, findings, Path(a.report))
        print(f"[IR] 报告已生成：{a.report}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Linux 入侵排查（只读取证）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p0 = sub.add_parser("scan")
    p0.add_argument("--root", required=True, help="导出的文件系统根目录")
    p0.add_argument("--report", default=None, help="输出 Markdown IR 报告")
    p0.add_argument("--json", default=None, help="输出结构化结果")
    p0.set_defaults(func=cmd_scan)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)

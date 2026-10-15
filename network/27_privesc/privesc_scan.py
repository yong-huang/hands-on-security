#!/usr/bin/env python3
# =============================================================================
# 27 · 提权点扫描器（linpeas 精简思路）——以「当前用户」视角找不该存在的东西
#   ① SUID/SGID 全盘扫描：白名单外偏差 + 与 GTFOBins 工具「字节一致」的副本
#   ② sudo 规则：sudo -n -l 免密列举；NOPASSWD × 可逃逸程序（awk/find/vim…）
#   ③ cron 审计：PATH 含可写目录 / 命令可被劫持 / 脚本可写
#   ④ 可写敏感文件：/etc/passwd、/etc/sudoers、cron 配置……
#   ⑤ 修复清单（随报告输出）
# 说明: GTFOBins = 公开维护的「合法系统工具被滥用来逃逸提权」清单
# 用法: python3 privesc_scan.py [--json out.json]
# =============================================================================
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path

DEFAULT_SET = {  # ubuntu 22.04（装 sudo 后）发行版默认的 SUID/SGID 白名单——基线偏差才是信号
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd", "/usr/bin/mount",
    "/usr/bin/newgrp", "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/sudo",
    "/usr/bin/umount",
    "/usr/bin/chage", "/usr/bin/crontab", "/usr/bin/expiry",
    "/usr/sbin/pam_extrausers_chkpwd", "/usr/sbin/unix_chkpwd",
}
GTFOBINS = ["bash", "sh", "dash", "find", "awk", "vim", "vi", "less", "more",
            "python3", "python", "perl", "env", "tar", "cp", "mv", "sed",
            "tee", "xxd", "tcpdump", "nmap", "zip", "gdb", "make"]
SENSITIVE = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab",
             "/usr/local/bin/daily-backup"]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def walk_suid():
    hits = []
    for root, dirs, files in os.walk("/", onerror=lambda e: None):
        if root.startswith(("/proc", "/sys", "/dev")):
            dirs[:] = []
            continue
        for f in files:
            p = os.path.join(root, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_mode & 0o6000:
                hits.append({"path": p, "suid": bool(st.st_mode & 0o4000),
                             "mode": oct(st.st_mode & 0o7777), "uid": st.st_uid})
    return sorted(hits, key=lambda x: x["path"])


def gtfo_twin(path):
    """与系统里同名 GTFOBins 工具字节一致（被复制的副本）→ 返回原件路径"""
    for name in GTFOBINS:
        for base in ("/bin", "/usr/bin", "/sbin", "/usr/sbin"):
            cand = f"{base}/{name}"
            if os.path.isfile(cand):
                try:
                    if os.path.getsize(cand) == os.path.getsize(path) and sha(cand) == sha(path):
                        return cand
                except OSError:
                    pass
    return None


def _plantable(d):
    """目录不存在时，找最近的存在祖先，看当前用户能否把它逐级建出来"""
    cur = d
    while cur and not os.path.exists(cur):
        parent = os.path.dirname(cur.rstrip("/"))
        if parent == cur:
            return False
        cur = parent
    return bool(cur) and os.path.isdir(cur) and os.access(cur, os.W_OK)


def scan_sudo():
    try:
        r = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return {"ok": False, "raw": "未安装 sudo"}
    if r.returncode != 0:
        return {"ok": False, "raw": (r.stderr + r.stdout).strip()}
    cmds = re.findall(r"NOPASSWD:\s*(\S+)", r.stdout)
    return {"ok": True, "nopasswd": sorted(set(cmds))}


def scan_cron():
    files = ["/etc/crontab"] + sorted(str(p) for p in Path("/etc/cron.d").glob("*"))
    findings, checked = [], []
    for f in files:
        try:
            text = Path(f).read_text(errors="replace")
        except OSError:
            continue
        cur_path, ran = "/usr/bin:/bin", False
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("PATH="):
                cur_path = line.split("=", 1)[1].strip()
                continue
            m = re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(.+)$", line)
            if not m:
                continue
            user, cmd = m.group(1), m.group(2).strip()
            prog = cmd.split()[0]
            ran = True
            if "/" not in prog:
                # 沿 PATH 找「第一个可动手的地方」：文件可写 / 目录可写 / 目录可创建
                for d in cur_path.split(":"):
                    cand = os.path.join(d, prog)
                    if os.path.exists(cand):
                        if os.access(cand, os.W_OK):
                            findings.append(f"{f}：命令 {prog} 当前解析到 {cand}，且可被改写")
                        break
                    if os.path.isdir(d) and os.access(d, os.W_OK):
                        findings.append(f"{f}：命令 {prog} 的首个可写解析目录 {d} 里还没有它"
                                        f"——植入同名文件即劫持（发车用户 {user}）")
                        break
                    if not os.path.exists(d) and _plantable(d):
                        findings.append(f"{f}：命令 {prog} 的解析目录 {d} 不存在但可由当前用户"
                                        f"创建——建成并植入同名文件即劫持（发车用户 {user}）")
                        break
            for tok in cmd.split():
                if tok.startswith("/") and os.path.exists(tok) and os.access(tok, os.W_OK):
                    findings.append(f"{f}：脚本 {tok} 可被当前用户改写")
        if ran:
            checked.append(f)
    return findings, checked


def main():
    as_json = "--json" in sys.argv
    out_path = sys.argv[sys.argv.index("--json") + 1] if as_json else None
    findings = {"suid": [], "sudo": [], "cron": [], "writable": []}

    print(f"[27] 提权点扫描 · 当前用户 {pwd.getpwuid(os.getuid()).pw_name}（uid={os.getuid()}）")

    suid = walk_suid()
    extra = [s for s in suid if s["path"] not in DEFAULT_SET]
    n_suid = sum(1 for s in suid if s["suid"])
    print(f"\n== ① SUID/SGID：共 {len(suid)} 个（SUID {n_suid} / SGID {len(suid) - n_suid}；白名单外 {len(extra)} 个） ==")
    for s in extra:
        twin = gtfo_twin(s["path"])
        kind = "SUID" if s["suid"] else "SGID"
        line = f"  [!] {s['path']}（{kind} {s['mode']} uid={s['uid']}）——白名单外"
        if twin:
            line += f"，且与 {twin} 字节一致 → GTFOBins 可直接逃逸"
        print(line)
        findings["suid"].append({"path": s["path"], "twin": twin})
    if len(extra) != len(suid):
        print(f"  ✓ 其余 {len(suid) - len(extra)} 个与发行版默认白名单一致")

    print("\n== ② sudo 规则（sudo -n -l） ==")
    sd = scan_sudo()
    if sd["ok"]:
        for cmd in sd["nopasswd"]:
            base = os.path.basename(cmd)
            if base in GTFOBINS:
                print(f"  [!] NOPASSWD: {cmd} → GTFOBins 可逃逸（如 awk 'BEGIN{{system(\"/bin/sh\")}}'）")
                findings["sudo"].append({"command": cmd, "gtfobins": True})
            else:
                print(f"  [!] NOPASSWD: {cmd}")
                findings["sudo"].append({"command": cmd, "gtfobins": False})
    else:
        print(f"  · 免密列举失败（{sd['raw'].splitlines()[0][:60] if sd['raw'] else '无输出'}）")
        print("  · 低权盲区：真实环境 sudoers 未必可读——这也是 linpeas 的局限之一")

    print("\n== ③ cron 审计（/etc/crontab + /etc/cron.d/*） ==")
    cron_findings, checked = scan_cron()
    for c in cron_findings:
        print(f"  [!] {c}")
    findings["cron"] = cron_findings
    for f in checked:
        if not any(c.startswith(f) for c in cron_findings):
            print(f"  ✓ {f}：未发现可劫持点")

    print("\n== ④ 可写敏感文件 ==")
    w = [p for p in SENSITIVE + sorted(str(Path('/etc/sudoers.d').glob('*'))) + sorted(str(Path('/etc/cron.d').glob('*')))
         if os.path.exists(p) and os.access(p, os.W_OK)]
    findings["writable"] = w
    if w:
        for p in w:
            print(f"  [!] {p} 可被当前用户改写")
    else:
        print(f"  ✓ /etc/passwd、/etc/sudoers、cron 配置等均不可写")

    print("\n== ⑤ 修复清单 ==")
    fixes = []
    if findings["suid"]:
        fixes.append("移除白名单外 SUID：rm 或 chmod u-s（SUID 副本是 GTFOBins 的第一入口）")
    if findings["sudo"]:
        fixes.append("visudo 收紧：删掉 NOPASSWD 直通可逃逸程序，改用不可逃逸的专用包装脚本")
    if findings["cron"]:
        fixes.append("cron 任务 PATH 只留 /usr/bin:/bin，命令一律绝对路径，脚本 755 root:root")
    if findings["writable"]:
        fixes.append("将报告中的可写敏感文件收回 root:root 644 及以下")
    fixes.append("回归：本脚本重跑应 0 告警——修复前先立「准入线」")
    for i, f in enumerate(fixes, 1):
        print(f"  {i}) {f}")

    print(f"\n检出：白名单外 SUID {len(findings['suid'])} 个 / NOPASSWD {len(findings['sudo'])} 条"
          f" / cron 可劫持 {len(findings['cron'])} 处 / 可写敏感文件 {len(findings['writable'])} 个")
    if out_path:
        Path(out_path).write_text(json.dumps({"user": pwd.getpwuid(os.getuid()).pw_name,
                                              "suid": suid, "findings": findings},
                                             ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

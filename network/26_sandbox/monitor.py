#!/usr/bin/env python3
# =============================================================================
# 26 · 恶意行为监控沙箱——三路采集 + 规则评分 + Markdown 画像报告
#   ① 进程树：psutil 0.2s 轮询，记录样本进程树下每个进程的首次出现
#   ② 文件变更：watchdog（inotify）盯沙箱目录，记录 创建/删除/修改
#   ③ 网络外联：轮询进程 TCP 连接快照 + 内置 C2 陷阱（HTTP 心跳计数）
#   用法: python3 monitor.py run --sample samples/malicious.py \
#            --sandbox-root /sandbox --victim /sandbox/victim \
#            --beacon-port 9099 --timeout 30 --json /work/behavior.json \
#            --report /work/report.md
# =============================================================================
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

SUSPICIOUS_EXTS = {".locked", ".enc", ".crypt", ".crypto"}
RANSOM_RE = re.compile(r"(README|DECRYPT|RECOVER|HOW_?TO)", re.I)


# ---------------------------------------------------------------- 文件变更
class FsCollector(FileSystemEventHandler):
    """watchdog 事件 → 统一事件表（只记文件，不记目录）"""

    def __init__(self, root, t0):
        self.root, self.t0 = root, t0
        self.lock, self.events = threading.Lock(), []

    def _rec(self, kind, path):
        with self.lock:
            self.events.append({"t": round(time.monotonic() - self.t0, 2), "kind": kind, "path": path})

    def on_created(self, e):
        if not e.is_directory:
            self._rec("created", e.src_path)

    def on_deleted(self, e):
        if not e.is_directory:
            self._rec("deleted", e.src_path)

    def on_modified(self, e):
        if not e.is_directory:
            self._rec("modified", e.src_path)

    def on_moved(self, e):
        if not e.is_directory:
            self._rec("moved", e.dest_path)


# ---------------------------------------------------------------- 进程树
class ProcCollector(threading.Thread):
    """0.2s 轮询：凡是「能沿父链走到样本根进程」的都算树内，记首次出现"""

    def __init__(self, root_pid, t0):
        super().__init__(daemon=True)
        self.root_pid, self.t0 = root_pid, t0
        self.stop_flag, self.lock = threading.Event(), threading.Lock()
        self.tree = {}  # pid → {name, depth, cmd, t}

    def _depth(self, pid, snap):
        depth, cur = 0, pid
        while cur in snap and snap[cur].get("ppid") and cur != self.root_pid:
            cur = snap[cur]["ppid"]
            depth += 1
            if depth > 8:
                return None
        return depth if cur == self.root_pid else None

    def run(self):
        while not self.stop_flag.is_set():
            snap = {}
            for p in psutil.process_iter(["pid", "ppid", "name", "cmdline"]):
                snap[p.info["pid"]] = p.info
            with self.lock:
                for pid, info in snap.items():
                    if pid in self.tree:
                        continue
                    d = self._depth(pid, snap)
                    if d is None:
                        continue
                    cmd = " ".join(info["cmdline"] or [])
                    self.tree[pid] = {"name": info["name"], "depth": d,
                                      "cmd": cmd[:80], "t": round(time.monotonic() - self.t0, 2)}
            time.sleep(0.2)

    def stop(self):
        self.stop_flag.set()
        self.join(timeout=2)


def _tcp_conns(proc):
    """psutil 5.9.0（jammy 自带）叫 connections()，5.9.8+ 改名 net_connections()"""
    fn = getattr(proc, "net_connections", None) or getattr(proc, "connections", None)
    return fn(kind="tcp") if fn else []


# ---------------------------------------------------------------- 网络外联
class NetCollector(threading.Thread):
    """C2 陷阱（HTTP 心跳计数）+ 进程 TCP 连接快照（远端端点去重）"""

    def __init__(self, port, proc_collector, t0):
        super().__init__(daemon=True)
        self.port, self.pc, self.t0 = port, proc_collector, t0
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()
        self.hits, self.endpoints = [], {}  # hits: (t, path)；endpoints: (ip,port) → t

    def _serve(self, srv):
        while not self.stop_flag.is_set():
            try:
                conn, _ = srv.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                req = conn.recv(256).decode(errors="replace")
                path = (req.split(" ")[1] if " " in req else "/?")
                with self.lock:
                    self.hits.append({"t": round(time.monotonic() - self.t0, 2), "path": path})
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    def run(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(8)
        srv.settimeout(0.3)
        threading.Thread(target=self._serve, args=(srv,), daemon=True).start()
        while not self.stop_flag.is_set():
            with self.pc.lock:
                pids = list(self.pc.tree)
            for pid in pids:
                try:
                    for c in _tcp_conns(psutil.Process(pid)):
                        if c.raddr:
                            with self.lock:
                                self.endpoints.setdefault((c.raddr.ip, c.raddr.port),
                                                          round(time.monotonic() - self.t0, 2))
                except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
                    pass
            time.sleep(0.2)
        srv.close()

    def stop(self):
        self.stop_flag.set()
        self.join(timeout=2)


# ---------------------------------------------------------------- 规则引擎
def detect(fs_events, tree, hits, endpoints, root_pid):
    """返回检出列表：类别 / 分值 / 高危 / 首次时间 / 证据"""
    created = [e for e in fs_events if e["kind"] == "created"]
    deleted = [e for e in fs_events if e["kind"] == "deleted"]
    locked = [e for e in created if e["path"].endswith(".locked")]
    hidden = [e for e in created if Path(e["path"]).name.startswith(".")]
    ransom = [e for e in created if RANSOM_RE.search(Path(e["path"]).name)]
    exts = {Path(e["path"]).suffix for e in locked}
    children = [p for pid, p in tree.items() if pid != root_pid]
    max_depth = max((p["depth"] for p in tree.values()), default=0)

    def t_of(items):
        return min(i["t"] for i in items) if items else None

    rules = [
        ("批量加密文件（.locked 落盘）", 30, True, len(locked) >= 3, t_of(locked),
         f"{len(locked)} 个新文件带 .locked 后缀（首例：{locked[0]['path']}）" if locked else ""),
        ("定时外联（HTTP 心跳）", 25, True, len(hits) >= 3, t_of(hits),
         f"C2 陷阱收到 {len(hits)} 次 /beacon 请求（远端 "
         f"{sorted(f'{ip}:{p}' for ip, p in endpoints) or ['?']}）" if hits else ""),
        ("勒索说明文件落盘", 15, True, bool(ransom), t_of(ransom),
         f"创建 {ransom[0]['path']}（文件名命中勒索话术）" if ransom else ""),
        ("可疑扩展名批量出现", 15, True, len(exts) >= 1 and len(locked) >= 3, t_of(locked),
         f"扩展名集合 {sorted(exts)}，共 {len(locked)} 例" if locked else ""),
        ("原件被批量删除", 10, False, len(deleted) >= 3, t_of(deleted),
         f"{len(deleted)} 个原始文件被删除（首例：{deleted[0]['path']}）" if deleted else ""),
        ("隐藏文件写入", 10, False, bool(hidden), t_of(hidden),
         f"创建隐藏文件 {hidden[0]['path']}" if hidden else ""),
        ("进程树异常（拉起子进程）", 10, False, len(children) >= 1 and max_depth >= 1, t_of(list(children)),
         f"样本树下出现 {len(children)} 个子进程（最深 {max_depth} 层）" if children else ""),
    ]
    findings = []
    for idx, (name, score, hot, hit, t, evidence) in enumerate(rules):
        if hit:
            findings.append({"category": name, "score": score, "high": hot,
                             "t": t, "order": idx, "evidence": evidence})
    return findings


# ---------------------------------------------------------------- 报告
def verdict_of(total):
    if total >= 60:
        return "高度疑似恶意行为"
    if total >= 20:
        return "存在可疑行为"
    return "未见明显恶意行为"


def write_report(path, sample_name, duration, tree, fs_events, hits, endpoints, findings, total):
    created = [e for e in fs_events if e["kind"] == "created"]
    deleted = [e for e in fs_events if e["kind"] == "deleted"]
    modified = [e for e in fs_events if e["kind"] == "modified"]
    children = [p for pid, p in tree.items() if p["depth"] >= 1]
    max_depth = max((p["depth"] for p in tree.values()), default=0)
    lines = [
        f"# 行为画像报告 · 样本 {sample_name}",
        "",
        "## 1. 概览",
        "",
        f"- 运行时长：T+{duration}s",
        f"- 进程树：{len(tree)} 个进程（最深 {max_depth} 层，子进程 {len(children)} 个）",
        f"- 文件事件：创建 {len(created)} / 删除 {len(deleted)} / 修改 {len(modified)}",
        f"- 网络：/beacon 命中 {len(hits)} 次；连接快照远端 {sorted(f'{ip}:{p}' for ip, p in endpoints)}",
        "",
        "## 2. 行为时间线",
        "",
        "| 相对时间 | 类别 | 证据摘要 |",
        "|:---|:---|:---|",
    ]
    # 时间线两键排序：先 0.1s 桶再规则序——同一批事件的先后不受毫秒抖动影响
    for f in sorted(findings, key=lambda x: (round(x["t"], 1), x["order"])):
        lines.append(f"| T+{f['t']}s | {f['category']} | {f['evidence']} |")
    lines += ["", "## 3. 检出项明细", ""]
    for f in findings:
        tag = "高危" if f["high"] else "线索"
        lines.append(f"- **{f['category']}**（+{f['score']}，{tag}）：{f['evidence']}")
    lines += ["", "## 4. 评分与结论", "",
              f"总分 **{total}** → **{verdict_of(total)}**", ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------- 主流程
def run(args):
    victim = Path(args.victim)
    if not victim.is_dir():
        sys.exit(f"缺靶目录 {victim}（由沙箱脚本准备）")
    t0 = time.monotonic()
    fs = FsCollector(args.sandbox_root, t0)
    obs = Observer()
    obs.schedule(fs, args.sandbox_root, recursive=False)
    obs.schedule(fs, str(victim), recursive=False)
    obs.start()

    env = dict(os.environ, SANDBOX_ROOT=args.sandbox_root, SANDBOX_VICTIM=args.victim,
               SANDBOX_C2=f"127.0.0.1:{args.beacon_port}")
    proc = subprocess.Popen([sys.executable, args.sample], env=env)
    pc = ProcCollector(proc.pid, t0)
    pc.start()
    nc = NetCollector(args.beacon_port, pc, t0)
    nc.start()
    try:
        proc.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        for c in psutil.Process(proc.pid).children(recursive=True):
            c.kill()
        proc.kill()
    time.sleep(0.8)  # 沉淀
    obs.stop()
    obs.join()
    pc.stop()
    nc.stop()

    duration = round(time.monotonic() - t0, 1)
    with fs.lock, pc.lock, nc.lock:
        fs_events, tree, hits, endpoints = list(fs.events), dict(pc.tree), list(nc.hits), dict(nc.endpoints)
    findings = detect(fs_events, tree, hits, endpoints, proc.pid)
    total = sum(f["score"] for f in findings)
    print(f"[26] 样本 {Path(args.sample).name}：进程树 {len(tree)} 个（最深 "
          f"{max(p['depth'] for p in tree.values()) if tree else 0} 层），"
          f"文件事件 创建 {sum(1 for e in fs_events if e['kind'] == 'created')} / "
          f"删除 {sum(1 for e in fs_events if e['kind'] == 'deleted')}")
    print(f"[26] 外联：/beacon 命中 {len(hits)} 次；连接快照远端 "
          f"{sorted(f'{ip}:{p}' for ip, p in endpoints)}")
    print(f"[26] 检出 {len(findings)} 类行为 → 评分 {total} → {verdict_of(total)}")
    Path(args.json).write_text(json.dumps(
        {"sample": Path(args.sample).name, "duration": duration,
         "processes": list(tree.values()),
         "fs_events": fs_events, "beacon_hits": hits,
         "endpoints": [f"{ip}:{p}" for ip, p in endpoints],
         "findings": findings, "score": total, "verdict": verdict_of(total)},
        ensure_ascii=False, indent=1), encoding="utf-8")
    write_report(args.report, Path(args.sample).name, duration, tree,
                 fs_events, hits, endpoints, findings, total)


def main():
    p = argparse.ArgumentParser(description="26 · 恶意行为监控沙箱")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="监控一次样本运行并出报告")
    r.add_argument("--sample", required=True)
    r.add_argument("--sandbox-root", default="/sandbox")
    r.add_argument("--victim", default="/sandbox/victim")
    r.add_argument("--beacon-port", type=int, default=9099)
    r.add_argument("--timeout", type=int, default=30)
    r.add_argument("--json", default="behavior.json")
    r.add_argument("--report", default="report.md")
    run(p.parse_args())


if __name__ == "__main__":
    main()

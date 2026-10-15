#!/usr/bin/env python3
# =============================================================================
# 29 · 自建 mini-CTF 平台（flask 单文件）：6 道题 + flag 判分 + 计分板
#   题目：① 套娃编码 ② MD5 弱口令 ③ SQLite 注入 ④ XSS 偷管理员 cookie
#         ⑤ 日志取证 ⑥ ELF crackme 逆向
#   仅监听 127.0.0.1，本地教学用；状态（计分板）落 CTF_STATE 指定文件
#   环境变量: CTF_PORT / CTF_STATE / CTF_CRACKME / NODE_PATH（XSS 机器人）
# =============================================================================
import hashlib
import json
import os
import re
import subprocess
import sqlite3
import time
import urllib.parse
from pathlib import Path

from flask import Flask, Response, jsonify, request

BASE = Path(__file__).resolve().parent
PORT = int(os.environ.get("CTF_PORT", "8930"))
STATE = Path(os.environ.get("CTF_STATE", str(BASE / "artifacts" / "scoreboard.json")))
CRACKME = Path(os.environ.get("CTF_CRACKME", str(BASE / "artifacts" / "crackme29")))
BOT = BASE / "admin_bot.js"

FLAGS = {
    "c1": ("套娃编码", 100, "HOSEC29{n3st3d_c0d1ng_l4y3rs}"),
    "c2": ("MD5 弱口令", 100, "HOSEC29{w3ak_p4ssw0rd_cr4ck3d}"),
    "c3": ("SQLite 注入", 150, "HOSEC29{sql1_1nj3ct10n_byp4ss}"),
    "c4": ("XSS 偷 cookie", 150, "HOSEC29{adm1n_c00k13_st0l3n}"),
    "c5": ("日志取证", 100, "HOSEC29{l0g_f0r3ns1cs_w1ns}"),
    "c6": ("逆向 crackme", 150, "HOSEC29{r3v3rs3_0n3_st3p}"),
}

app = Flask(__name__)
T0 = time.monotonic()
DB = {"solved": {}}  # cid → {"points", "t"}
STOLEN = {"cookie": None}
C2_PASSWORD = "admin888"


def save_state():
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(DB, ensure_ascii=False, indent=1), encoding="utf-8")


# ---------------------------------------------------------------- ① 套娃编码
def nest_encode(text: str) -> str:
    blob = text.encode()
    blob = blob[::-1]                       # 反转
    blob = blob.hex().encode()              # hex
    for _ in range(3):
        blob = __import__("base64").b64encode(blob)
    return blob.decode()


# ---------------------------------------------------------------- ⑤ 日志题
def make_access_log() -> str:
    flag_enc = urllib.parse.quote(FLAGS["c5"][2], safe="")
    lines = []
    for i in range(40):
        lines.append(f'10.0.0.{10 + i % 30} - - [15/Oct/2026:03:{i:02d}:11 +0000] '
                     f'"GET /index.html HTTP/1.1" 200 {512 + i}')
    lines.append('10.0.0.66 - - [15/Oct/2026:03:14:07 +0000] '
                 f'"GET /upload?name=backup_{flag_enc}.zip HTTP/1.1" 200 1337')
    for i in range(41, 80):
        lines.append(f'10.0.0.{10 + i % 30} - - [15/Oct/2026:03:{i % 60 :02d}:42 +0000] '
                     f'"GET /static/app.js HTTP/1.1" 304 0')
    return "\n".join(lines) + "\n"


ACCESS_LOG = make_access_log()


# ---------------------------------------------------------------- 页面骨架
@app.get("/")
def index():
    rows = "".join(
        f"<li>{cid} · {title}（{pts} 分）{' ✅ 已解' if cid in DB['solved'] else ''}</li>"
        for cid, (title, pts, _) in FLAGS.items())
    return f"<h1>HOSEC29 mini-CTF</h1><ul>{rows}</ul><p>提交: POST /submit cid=.. flag=..</p>"


@app.get("/api/list")
def api_list():
    return jsonify([{"id": cid, "title": t, "points": p, "solved": cid in DB["solved"]}
                    for cid, (t, p, _) in FLAGS.items()])


@app.post("/submit")
def submit():
    cid = request.form.get("cid", "")
    flag = request.form.get("flag", "").strip()
    if cid not in FLAGS:
        return jsonify({"result": "unknown", "msg": "未知题号"}), 404
    if flag != FLAGS[cid][2]:
        return jsonify({"result": "wrong", "msg": "flag 不正确"})
    if cid in DB["solved"]:
        return jsonify({"result": "already", "msg": "已解出（不重复计分）",
                        "points": DB["solved"][cid]["points"]})
    DB["solved"][cid] = {"points": FLAGS[cid][1], "t": round(time.monotonic() - T0, 1)}
    save_state()
    return jsonify({"result": "correct", "points": FLAGS[cid][1]})


@app.get("/scoreboard")
def scoreboard():
    rows = [{"cid": cid, "title": FLAGS[cid][0], "points": v["points"], "t": v["t"]}
            for cid, v in DB["solved"].items()]
    rows.sort(key=lambda r: r["t"])
    if request.args.get("format") == "text":
        body = "名次 | 题号 | 题目 | 得分 | 用时\n" + "\n".join(
            f"{i} | {r['cid']} | {r['title']} | {r['points']} | T+{r['t']}s"
            for i, r in enumerate(rows, 1))
        total = sum(r["points"] for r in rows)
        return body + f"\n总分 {total} / 750\n"
    return jsonify({"solved": rows, "total": sum(r["points"] for r in rows), "max": 750})


# ---------------------------------------------------------------- ① 数据面
@app.get("/c1/data")
def c1_data():
    return Response(nest_encode(FLAGS["c1"][2]), mimetype="text/plain")


# ---------------------------------------------------------------- ② 数据面
@app.get("/c2/hash")
def c2_hash():
    return jsonify({"user": "admin", "md5": hashlib.md5(C2_PASSWORD.encode()).hexdigest(),
                    "hint": "常见弱口令词典即可命中"})


# ---------------------------------------------------------------- ③ SQLite 注入
@app.get("/c3/login")
def c3_login():
    u, p = request.args.get("u", ""), request.args.get("p", "")
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE users (name TEXT, pass TEXT, secret TEXT)")
    con.execute("INSERT INTO users VALUES ('admin', 'x9f2!kQ', ?)", (FLAGS["c3"][2],))
    con.execute("INSERT INTO users VALUES ('guest', 'guest', 'nothing here')")
    sql = f"SELECT name, secret FROM users WHERE name='{u}' AND pass='{p}'"
    try:
        row = con.execute(sql).fetchone()
    except sqlite3.Error as e:
        return f"SQL 错误：{e}", 500
    if row:
        return f"欢迎 {row[0]}！你的秘密：{row[1]}"
    return "登录失败"


# ---------------------------------------------------------------- ④ XSS
@app.get("/c4/msg")
def c4_msg():
    msg = STOLEN.get("msg") or "（留言板空空如也——POST msg= 留下第一条）"
    return f"<h1>留言板</h1><div id='board'>{msg}</div>"


@app.post("/c4/msg")
def c4_post():
    STOLEN["msg"] = request.form.get("msg", "")[:500]
    return "已留言"


@app.get("/c4/exfil")
def c4_exfil():
    STOLEN["cookie"] = request.args.get("c")
    return "ok"


@app.get("/c4/stolen")
def c4_stolen():
    return jsonify({"stolen": STOLEN["cookie"]})


@app.post("/c4/report")
def c4_report():
    """举报/上报留言——模拟「管理员会来看一眼」"""
    if not BOT.is_file():
        return jsonify({"result": "bot-missing"}), 500
    env = dict(os.environ)
    try:
        subprocess.run(["node", str(BOT), f"http://127.0.0.1:{PORT}/c4/msg",
                        f"admin_session={FLAGS['c4'][2]}"],
                       env=env, timeout=40, capture_output=True)
    except subprocess.TimeoutExpired:
        return jsonify({"result": "timeout"})
    return jsonify({"result": "admin-visited"})


# ---------------------------------------------------------------- ⑤ 数据面
@app.get("/c5/access.log")
def c5_log():
    return Response(ACCESS_LOG, mimetype="text/plain")


# ---------------------------------------------------------------- ⑥ 数据面
@app.get("/c6/crackme")
def c6_bin():
    if not CRACKME.is_file():
        return "crackme 未编译（先跑 ctf_lab.sh apply）", 500
    return Response(CRACKME.read_bytes(), mimetype="application/octet-stream")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, threaded=True)

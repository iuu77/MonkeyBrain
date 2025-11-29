#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
monkey_report_json_cli.py  –  命令行传参 + 动态命名 HTML 报告
"""
import json
import os
import html
import datetime
import requests
import argparse
import re
from typing import Dict

# API_KEY = os.getenv("KIMI_API_KEY")
API_KEY = "sk-MnTSkb654f4hYS7LHbT1DyI77H9t8WqLM94CHFWkY8cnm7LB"
API_URL = "https://api.moonshot.cn/v1/chat/completions"
MODEL   = "moonshot-v1-8k"

if not API_KEY:
    raise SystemExit("请先 export KIMI_API_KEY=sk-xxx")

# ----------- 专家话术 & 颜色 -----------
PROMPT_MAP: Dict[str, str] = {
    "crash": "你是 Android 崩溃分析专家，熟悉 kotlin / Java 崩溃堆栈。请根据下面日志，给出「根因分析」和「可落地的修复建议」，分点陈述，尽量简洁。",
    "anr": "你是 Android ANR 专家，熟悉主线程阻塞、锁竞争、I/O 等问题。请根据下面日志，给出「触发 ANR 的直接原因」和「避免再次出现的优化方案」，分点陈述。",
    "memory_leak": "你是 Android 内存优化专家，熟悉 LeakCanary / MAT / JVM GC。请根据下面日志，指出「泄漏对象」与「引用链关键路径」，并给出「修复或规避方案」，分点陈述。",
    "exception": "你是 Android 异常分析专家，熟悉 Java / Kotlin 各类受检与非受检异常。请根据下面日志，给出「异常触发原因」和「可落地的修复或防御方案」，分点陈述，尽量简洁。",
}
COLOR_MAP = {"crash": "#e74c3c", "anr": "#f39c12", "memory_leak": "#9b59b6", "exception": "#ff7043"}

# ----------- 调用 Kimi -----------
def ask_kimi(log_text: str, category: str) -> str:
    sys_prompt = PROMPT_MAP.get(category, PROMPT_MAP["crash"])
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": log_text},
        ],
        "temperature": 0.3,
        "max_tokens": 1000,
    }
    resp = requests.post(API_URL, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()

# ----------- HTML 生成 -----------
def build_html(category: str, process: str, pid: str, ts: str, raw: str, advice: str, log_path: str) -> str:
    color = COLOR_MAP.get(category, COLOR_MAP["crash"])
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>Monkey {category.upper()} 报告</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:40px;background:#fafafa}}
h1{{color:{color}}}
table{{width:100%;border-collapse:collapse;background:#fff}}
th,td{{padding:10px;border:1px solid #ddd;text-align:left}}
th{{background:#f2f2f2}}
.tag{{display:inline-block;padding:4px 10px;border-radius:4px;color:#fff;font-size:12px}}
pre{{white-space:pre-wrap;word-break:break-all;background:#f6f8fa;padding:8px;border-radius:4px}}
</style>
</head>
<body>
<h1>Monkey 稳定性分析报告</h1>
<p>生成时间：{datetime.datetime.now():%Y-%m-%d %H:%M:%S}</p>
<table>
<tr><th>类型</th><td><span class="tag" style="background:{color}">{category.upper()}</span></td></tr>
<tr><th>进程</th><td>{html.escape(process)}</td></tr>
<tr><th>PID</th><td>{pid}</td></tr>
<tr><th>时间</th><td>{html.escape(ts)}</td></tr>
<tr><th>原始日志路径</th><td><pre>{html.escape(log_path)}</pre></td></tr>
<tr><th>原始日志</th><td><pre>{html.escape(raw)}</pre></td></tr>
<tr><th>根因 & 解决建议</th><td><pre>{html.escape(advice)}</pre></td></tr>
</table>
</body>
</html>"""

# ----------- 主流程 -----------
def main():
    parser = argparse.ArgumentParser(description="Monkey JSON 日志 -> HTML 报告")
    parser.add_argument("json_file", help="json 日志文件路径")
    parser.add_argument("--log-path", default="", help="原始日志路径（可选）")
    args = parser.parse_args()

    if not os.path.isfile(args.json_file):
        raise SystemExit(f"文件不存在：{args.json_file}")

    data = json.load(open(args.json_file, encoding="utf-8"))
    category = data.get("category", "crash").lower()
    process  = data["processName"]
    # 先拿到 JSON 里的 UTC 时间并转成 local 时间
    ts_utc   = datetime.datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
    ts_local = ts_utc.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    ts_fmt   = ts_utc.astimezone().strftime("%Y%m%d_%H%M%S")
    raw      = "\n".join(data["context"])
     # 安全提取 PID（可能不存在）
    pid_match = re.search(r"pid (\d+)", raw, re.IGNORECASE)
    pid = pid_match.group(1) if pid_match else "未知"

    print(f"已提取 {category.upper()}，正在调用 Kimi API …")
    advice = ask_kimi(raw, category)

    html_doc = build_html(category, process, pid, ts_local,
                          raw, advice, args.log_path or args.json_file)
    # --------------- 输出结果到脚本当前路径下的output目录 ---------------
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(out_dir, exist_ok=True)
    safe_process = re.sub(r'[\\/:*?"<>|]', '_', process)
    out_name = os.path.join(out_dir, f"{category}_{safe_process}_{ts_fmt}.html")
    # ------------------------------------------------------------------
    with open(out_name, "w", encoding="utf-8") as f:
        f.write(html_doc)

    print(f"已生成 {out_name}，请用浏览器打开查看。")

if __name__ == "__main__":
    main()
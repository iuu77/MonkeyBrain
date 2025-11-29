#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
summarize_final.py  –  卡片折叠汇总，展开后嵌入完整单报告内容
"""
import os
import re
import glob
import html
import datetime
from pathlib import Path
from typing import List, Dict

REPORT_DIR = "output"
OUT_DIR    = REPORT_DIR

# ----------- 解析 -----------
def parse_html(path: str) -> Dict:
    text = Path(path).read_text(encoding="utf-8")

    # 类别
    cat_m = re.search(r'<span class="tag" style="background:#?\w+">(\w+)</span>', text)
    category = cat_m.group(1).lower() if cat_m else "unknown"

    # 进程 & 时间
    proc_m = re.search(r"<th>进程</th><td>(.*?)</td>", text, re.S)
    process = html.unescape(proc_m.group(1)) if proc_m else "unknown"
    time_m  = re.search(r"<th>时间</th><td>(.*?)</td>", text, re.S)
    ts      = html.unescape(time_m.group(1)) if time_m else "N/A"

    # 关键摘要
    raw_m = re.search(r"<th>原始日志</th><td><pre>(.*?)</pre></td>", text, re.S)
    raw_log = html.unescape(raw_m.group(1)) if raw_m else ""
    summary = _extract_summary(raw_log, category)

    # 完整建议区域（包含原始日志 + 建议）
    advice_m = re.search(r"<th>根因 & 解决建议</th><td><pre>(.*?)</pre></td>", text, re.S)
    advice = html.unescape(advice_m.group(1)) if advice_m else ""

    # 把原报告里的 <table> 整体搬过来（去掉外层 html/body 标签）
    table_m = re.search(r"<table>.*?</table>", text, re.S)
    full_table = table_m.group(0) if table_m else ""

    return {"file": os.path.basename(path),
            "category": category,
            "process": process,
            "time": ts,
            "summary": summary,
            "full_table": full_table}

def _extract_summary(log: str, cat: str) -> str:
    if cat == "crash":
        m = re.search(r"(\w+(Exception|Error)):", log)
        return m.group(1) if m else "Unknown Exception"
    if cat == "anr":
        m = re.search(r"Reason: (.*?)\n", log)
        return m.group(1).strip() if m else "Input dispatching timed out"
    if cat == "memory_leak":
        m = re.search(r"leak (canary)?:\s*(.*?)\n", log, re.I)
        return m.group(2).strip() if m else "Leak object"
    if cat == "exception":
        m = re.search(r"(\w+(Exception|Error)):", log)
        return m.group(1) if m else "Unknown Exception"
    return "Unknown"

# ----------- 新增：测试成功报告 -----------
def build_success_report() -> str:
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>Monkey 汇总报告</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:40px;background:#fafafa;color:#333;text-align:center}}
h1{{color:#27ae60}}
.tile{{display:inline-block;padding:14px 28px;border-radius:6px;background:#27ae60;color:#fff;font-size:20px;font-weight:bold;margin-top:40px}}
p{{margin-top:30px;color:#888}}
</style>
</head>
<body>
<h1>Monkey 稳定性汇总</h1>
<div class="tile">测试成功 · 无异常</div>
<p>生成时间：{datetime.datetime.now():%Y-%m-%d %H:%M:%S}</p>
</body>
</html>"""

# ----------- 主逻辑 -----------
def main():
    # 如果 output 目录不存在，也走“测试成功”分支
    if not os.path.isdir(REPORT_DIR):
        os.makedirs(REPORT_DIR, exist_ok=True)
        html_files = []
    else:
        html_files = glob.glob(os.path.join(REPORT_DIR, "*.html"))
        html_files = [f for f in html_files if "summary_" not in f]

    if not html_files:
        print(f"[WARN] {REPORT_DIR}/ 下未找到报告 html")
        # --------------- 新增：生成测试成功报告 ---------------
        out_name = f"summary_{datetime.datetime.now():%Y%m%d_%H%M%S}.html"
        Path(OUT_DIR, out_name).write_text(build_success_report(), encoding="utf-8")
        print(f"测试成功报告已生成：{os.path.join(OUT_DIR, out_name)}")
        # ------------------------------------------------------
        return

    records: List[Dict] = []
    for fp in html_files:
        try:
            records.append(parse_html(fp))
        except Exception as e:
            print(f"[SKIP] 解析失败 {fp} : {e}")

    # 严重程度排序
    severity = {"crash": 0, "exception": 1, "anr": 2, "memory_leak": 3}
    records.sort(key=lambda x: severity.get(x["category"], 999))

    stats: Dict[str, int] = {}
    for r in records:
        stats[r["category"]] = stats.get(r["category"], 0) + 1

    # ----------- 生成 HTML -----------
    tiles = "".join(
        f'<div class="tile {cat}" style="background:{color_map(cat)}">{cat.upper()} &nbsp;<span class="count">{cnt}</span></div>'
        for cat, cnt in sorted(stats.items(), key=lambda kv: severity.get(kv[0], 999))
    )

    cards = ""
    for rec in records:
        cards += f"""
<div class="card">
<details>
<summary>
<span class="tag {rec['category']}">{rec['category'].upper()}</span>
<span class="info">{html.escape(rec['process'])} – {html.escape(rec['time'])}</span>
<span class="summary">{html.escape(rec['summary'])}</span>
</summary>
<div class="inner">
{rec['full_table']}
</div>
</details>
</div>"""

    html_doc = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>Monkey 汇总报告</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:40px;background:#fafafa;color:#333}}
h1{{text-align:center}}
.tiles{{display:flex;gap:12px;justify-content:center;margin-bottom:30px}}
.tile{{padding:12px 24px;border-radius:6px;color:#fff;font-size:18px;font-weight:bold}}
.count{{font-size:24px;margin-left:6px}}
.crash{{background:#e74c3c}}
.exception{{background:#ff7043}}
.anr{{background:#f39c12}}
.memory_leak{{background:#9b59b6}}
.card{{background:#fff;border:1px solid #e0e0e0;border-radius:6px;margin-bottom:12px;box-shadow:0 2px 4px rgba(0,0,0,.05)}}
details{{padding:12px 16px}}
summary{{display:flex;align-items:center;cursor:pointer;font-weight:bold;outline:none}}
summary::-webkit-details-marker{{display:none}}
.tag{{display:inline-block;padding:4px 8px;border-radius:4px;color:#fff;font-size:12px;margin-right:10px}}
.info{{flex:1;margin-left:6px}}
.summary{{color:#777;font-size:14px;margin-left:10px}}
.inner{{margin-top:10px;border-top:1px solid #eee;padding-top:10px}}
table{{width:100%;border-collapse:collapse;background:#fff}}
th,td{{padding:8px 12px;border:1px solid #ddd;text-align:left;font-size:14px}}
th{{background:#f2f2f2}}
pre{{white-space:pre-wrap;word-break:break-all;background:#f6f8fa;padding:10px;border-radius:4px;margin-top:6px}}
</style>
</head>
<body>
<h1>Monkey 稳定性汇总</h1>
<div class="tiles">{tiles}</div>
{cards}
<hr>
<p style="text-align:center;color:#888">生成时间：{datetime.datetime.now():%Y-%m-%d %H:%M:%S}</p>
</body>
</html>"""

    out_name = f"summary_{datetime.datetime.now():%Y%m%d_%H%M%S}.html"
    Path(OUT_DIR, out_name).write_text(html_doc, encoding="utf-8")
    print(f"卡片汇总完成：{os.path.join(OUT_DIR, out_name)}")

def color_map(cat: str) -> str:
    return {"crash": "#e74c3c", "exception": "#ff7043", "anr": "#f39c12", "memory_leak": "#9b59b6"}.get(cat, "#7f8c8d")

if __name__ == "__main__":
    main()
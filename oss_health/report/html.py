"""单文件 HTML 报告（内嵌 CSS，无外部依赖）。"""

from __future__ import annotations

import html
from typing import Optional

from ..cvss import score_to_grade_zh
from ..models import ScanReport
from . import common


def _e(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _score_color(score: float) -> str:
    if score >= 80:
        return "#16a34a"
    if score >= 65:
        return "#65a30d"
    if score >= 50:
        return "#d97706"
    return "#dc2626"


def _status_class(status: str) -> str:
    return {"good": "ok", "warn": "warn", "bad": "bad"}.get(status, "muted")


def render(report: ScanReport) -> str:
    style = _css()
    score = report.score_int
    color = _score_color(score)
    verdict_icon = common.VERDICT_ICONS.get(report.verdict_level, "🟡")
    confidence = common.CONFIDENCE_LABELS.get(report.confidence, report.confidence)
    repo_line = common.repo_line(report) or "未找到 GitHub 仓库"

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="zh-CN">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>开源项目健康度报告 · {_e(common.short_target(report))}</title>")
    parts.append(f"<style>{style}</style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append('<div class="wrap">')

    # hero
    parts.append('<header class="hero">')
    parts.append('<div class="hero-text">')
    parts.append('<div class="eyebrow">开源项目健康度扫描器 · 报告</div>')
    parts.append(f'<h1>{_e(report.package.name if report.package else report.target.name)}</h1>')
    parts.append(
        f'<div class="target"><code>{_e(common.short_target(report))}</code>'
        f'<span class="sep">·</span>{_e(repo_line)}</div>'
    )
    parts.append(
        f'<div class="meta">采集于 {report.generated_at.strftime("%Y-%m-%d %H:%M UTC")}'
        f' · 统计窗口近 {report.extra.get("window_days", 90)} 天'
        f' · 耗时 {report.duration_seconds:.1f}s'
        f'{" · 离线快照" if report.offline else ""}</div>'
    )
    parts.append("</div>")
    parts.append(
        f'<div class="ring" style="--pct:{score};--ring:{color}">'
        f'<div class="ring-inner"><b>{score}</b><span>/ 100</span></div></div>'
    )
    parts.append("</header>")

    # verdict banner
    parts.append(f'<div class="verdict {report.verdict_level}">')
    parts.append(f'<div class="verdict-main">{verdict_icon} <strong>{_e(report.grade)} 级</strong> · {_e(report.verdict)}</div>')
    parts.append(
        f'<div class="verdict-sub">置信度 {_e(confidence)} · 加权原始分 {report.raw_total}</div>'
    )
    parts.append("</div>")

    # hard flags
    if report.hard_flags:
        parts.append('<section class="card flags">')
        parts.append('<h2>触发的一票否决</h2><ul>')
        for flag in report.hard_flags:
            parts.append(f'<li class="bad">⛔ {_e(flag.reason)} → 总分封顶 {flag.cap:.0f}</li>')
        parts.append("</ul></section>")

    # dimensions
    parts.append('<section class="card"><h2>维度评分</h2><div class="dims">')
    for dim in report.dimensions:
        if dim.available:
            pct = max(0, min(100, dim.score))
            parts.append('<div class="dim">')
            parts.append(
                f'<div class="dim-head"><span class="dim-title">{_e(dim.title)}</span>'
                f'<span class="dim-score">{dim.score}<small>/100</small></span></div>'
                f'<div class="track"><i style="width:{pct}%;background:{_score_color(pct)}"></i></div>'
                f'<div class="dim-status {_status_class(dim.status)}">'
                f'{_e(common.STATUS_LABELS.get(dim.status, dim.status))} · 权重 {dim.weight:.0f}%</div>'
                f'<p>{_e(common.evidence_summary(dim, 2))}</p>'
            )
            parts.append("</div>")
        else:
            parts.append(
                f'<div class="dim muted"><div class="dim-head">'
                f'<span class="dim-title">{_e(dim.title)}</span><span class="dim-score">—</span></div>'
                f'<p>{_e(dim.notes[0] if dim.notes else "数据缺失")}</p></div>'
            )
    parts.append("</div></section>")

    # findings
    findings = common.top_findings(report)
    parts.append('<section class="card"><h2>风险与发现</h2>')
    if findings:
        parts.append("<ul class=\"findings\">")
        for status, text, points in findings:
            parts.append(
                f'<li class="{_status_class(status)}">{_e(text)}'
                f'<span class="points">-{points}</span></li>'
            )
        parts.append("</ul>")
    else:
        parts.append('<p class="ok">✔ 未发现明显风险信号</p>')
    for positive in common.positives(report, 2):
        parts.append(f'<p class="positive">✔ {_e(positive)}</p>')
    parts.append("</section>")

    # vulnerabilities
    security = report.security
    if security is not None and security.db_available:
        parts.append('<section class="card"><h2>漏洞明细</h2>')
        parts.append(
            f'<p class="summary">当前版本 <code>{_e(security.version)}</code>：'
            f'<b>{len(security.vulns_current)}</b> 条未修复漏洞；'
            f'历史公告 {security.history_count} 条，其中 {security.fixed_count} 条已修复。</p>'
        )
        if security.vulns_current:
            parts.append('<div class="table-wrap"><table><thead><tr>'
                         "<th>编号</th><th>严重度</th><th>CVSS</th><th>摘要</th><th>修复版本</th><th>公开时间</th>"
                         "</tr></thead><tbody>")
            for vuln in security.vulns_current[:25]:
                sev = vuln.severity.lower()
                parts.append(
                    "<tr>"
                    f'<td><a href="{_e(vuln.url)}" target="_blank" rel="noreferrer">{_e(vuln.cve or vuln.id)}</a></td>'
                    f'<td><span class="sev {_e(sev)}">{_e(score_to_grade_zh(vuln.severity))}</span></td>'
                    f'<td class="num">{_e(f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "—")}</td>'
                    f"<td>{_e(vuln.summary)}</td>"
                    f'<td>{_e(vuln.best_fix_version or "无")}</td>'
                    f'<td>{_e(vuln.published.strftime("%Y-%m-%d") if vuln.published else "—")}</td>'
                    "</tr>"
                )
            parts.append("</tbody></table></div>")
            if len(security.vulns_current) > 25:
                parts.append(f'<p class="muted">仅展示前 25 条，完整数据见 JSON 报告。</p>')
        elif not security.vulns_current:
            parts.append('<p class="ok">✔ 未发现影响当前版本的已知漏洞</p>')
        parts.append("</section>")

    # dependency risks
    risky = [r for r in report.dep_risks if getattr(r, "vulns", None)]
    dep_dim = report.dimension("dependencies")
    if dep_dim is not None and dep_dim.metrics:
        parts.append('<section class="card"><h2>直接依赖安全</h2>')
        parts.append(
            f'<p class="summary">检查 {dep_dim.metrics.get("deps_checked", 0)}/'
            f'{dep_dim.metrics.get("deps_total", 0)} 个直接运行时依赖，'
            f'{dep_dim.metrics.get("deps_with_vulns", 0)} 个存在已知漏洞。</p>'
        )
        if risky:
            parts.append('<div class="table-wrap"><table><thead><tr>'
                         "<th>依赖</th><th>检查版本</th><th>编号</th><th>严重度</th><th>CVSS</th><th>摘要</th><th>修复版本</th>"
                         "</tr></thead><tbody>")
            for risk in risky:
                for vuln in risk.vulns[:6]:
                    parts.append(
                        "<tr>"
                        f"<td><code>{_e(risk.name)}</code></td>"
                        f"<td>{_e(risk.checked_version)}</td>"
                        f'<td><a href="{_e(vuln.url)}" target="_blank" rel="noreferrer">{_e(vuln.cve or vuln.id)}</a></td>'
                        f'<td><span class="sev {_e(vuln.severity.lower())}">{_e(score_to_grade_zh(vuln.severity))}</span></td>'
                        f'<td class="num">{_e(f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "—")}</td>'
                        f"<td>{_e(vuln.summary)}</td>"
                        f'<td>{_e(vuln.best_fix_version or "无")}</td>'
                        "</tr>"
                    )
            parts.append("</tbody></table></div>")
        else:
            parts.append('<p class="ok">✔ 直接依赖中未发现已知漏洞</p>')
        parts.append("</section>")

    # framework
    if report.framework is not None and report.framework.status != "unknown":
        fw = report.framework
        parts.append('<section class="card"><h2>运行时 / 框架支持</h2>')
        parts.append(
            f'<p><b>{_e(fw.runtime)}</b> · 声明支持：{_e("、".join(fw.declared) or "—")}'
            f' · 官方最新：<code>{_e(fw.latest_supported)}</code>'
            f' · 仍在支持：{_e("、".join(fw.supported_cycles) or "—")}</p>'
        )
        if fw.evidence:
            parts.append("<ul>")
            for evidence in fw.evidence:
                parts.append(f"<li>{_e(evidence)}</li>")
            parts.append("</ul>")
        parts.append("</section>")

    # recommendations
    parts.append('<section class="card"><h2>行动建议</h2><ol class="recs">')
    for rec in report.recommendations:
        parts.append(f"<li>{_e(rec)}</li>")
    parts.append("</ol></section>")

    # warnings
    if report.warnings:
        parts.append('<section class="card"><h2>数据警告 / 降级说明</h2><ul class="warnings">')
        for warning in report.warnings:
            parts.append(f"<li>{_e(warning)}</li>")
        parts.append("</ul></section>")

    # footer
    parts.append('<footer>')
    parts.append(f"<p><b>数据来源：</b>{_e(common.source_names(report))}</p>")
    if report.confidence_reasons:
        parts.append("<p><b>置信度说明：</b></p><ul class=\"reasons\">")
        for reason in report.confidence_reasons[:8]:
            parts.append(f"<li>{_e(reason)}</li>")
        parts.append("</ul>")
    parts.append(
        "<p class=\"limits\">已知局限：Issue / PR 统计基于最近 100 条采样；PR 合并者仅抽查少量已合并 PR；"
        "漏洞数据来自 OSV.dev；依赖按锁定版本或当前最新版本启发式检查，并非完整 SBOM 审计；"
        "运行时支持周期来自 endoflife.date；报告仅供决策参考。</p>"
    )
    parts.append(f"<p class=\"muted\">由 {_e(report.tool_version)} 生成</p>")
    parts.append("</footer>")

    parts.append("</div></body></html>")
    return "\n".join(parts)


def _css() -> str:
    return """
:root {
  --bg: #f6f7f9; --card: #ffffff; --text: #111827; --muted: #6b7280;
  --border: #e5e7eb; --good: #16a34a; --warn: #d97706; --bad: #dc2626;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
    "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  line-height: 1.6; font-size: 15px;
}
.wrap { max-width: 980px; margin: 0 auto; padding: 28px 20px 60px; }
.hero {
  display: flex; align-items: center; justify-content: space-between; gap: 24px;
  background: linear-gradient(135deg, #111827 0%, #1f2937 55%, #0f766e 100%);
  color: #fff; border-radius: 18px; padding: 28px 30px;
  box-shadow: 0 12px 30px rgba(17, 24, 39, .18);
}
.eyebrow { text-transform: uppercase; letter-spacing: .12em; font-size: 12px; opacity: .72; }
.hero h1 { margin: 6px 0 8px; font-size: 30px; line-height: 1.2; }
.target { font-size: 14px; opacity: .9; }
.target code { background: rgba(255,255,255,.14); padding: 2px 8px; border-radius: 6px; }
.target .sep { margin: 0 8px; opacity: .5; }
.meta { font-size: 12px; opacity: .62; margin-top: 8px; }
.ring {
  --pct: 0;
  width: 124px; height: 124px; flex: none; border-radius: 50%;
  background: conic-gradient(var(--ring) calc(var(--pct) * 1%), rgba(255,255,255,.16) 0);
  display: grid; place-items: center;
}
.ring-inner {
  width: 96px; height: 96px; border-radius: 50%; background: #111827;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.ring-inner b { font-size: 30px; line-height: 1; }
.ring-inner span { font-size: 11px; opacity: .6; }
.verdict {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  margin: 18px 2px 22px; padding: 14px 18px; border-radius: 12px;
  background: #fff; border: 1px solid var(--border); border-left: 5px solid var(--warn);
}
.verdict.good { border-left-color: var(--good); }
.verdict.caution { border-left-color: var(--warn); }
.verdict.bad { border-left-color: var(--bad); }
.verdict-main { font-size: 18px; }
.verdict-sub { color: var(--muted); font-size: 13px; }
.card {
  background: var(--card); border: 1px solid var(--border); border-radius: 14px;
  padding: 20px 22px; margin-bottom: 18px;
}
.card h2 { margin: 0 0 14px; font-size: 17px; }
.dims { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
.dim { border: 1px solid var(--border); border-radius: 10px; padding: 12px 14px; }
.dim.muted { opacity: .6; }
.dim-head { display: flex; justify-content: space-between; align-items: baseline; }
.dim-title { font-weight: 600; }
.dim-score { font-size: 22px; font-weight: 700; }
.dim-score small { font-size: 11px; color: var(--muted); font-weight: 400; }
.track { height: 8px; background: #f1f5f9; border-radius: 99px; overflow: hidden; margin: 8px 0 6px; }
.track i { display: block; height: 100%; border-radius: 99px; }
.dim-status { font-size: 12px; color: var(--muted); }
.dim p { margin: 6px 0 0; font-size: 12.5px; color: var(--muted); }
.dim-status.ok { color: var(--good); } .dim-status.warn { color: var(--warn); }
.dim-status.bad { color: var(--bad); }
ul { margin: 8px 0; padding-left: 20px; }
li { margin: 4px 0; }
.findings li.bad { color: #991b1b; } .findings li.warn { color: #92400e; }
.findings .points { margin-left: 8px; font-size: 12px; color: var(--muted); }
p.ok, .ok { color: var(--good); }
.positive { color: var(--muted); font-size: 13px; margin: 6px 0 0; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.sev { padding: 1px 8px; border-radius: 99px; font-size: 12px; white-space: nowrap; }
.sev.critical { background: #fee2e2; color: #991b1b; }
.sev.high { background: #ffedd5; color: #9a3412; }
.sev.medium { background: #fef9c3; color: #854d0e; }
.sev.low { background: #e0f2fe; color: #075985; }
a { color: #0f766e; }
.recs li { margin: 8px 0; }
.warnings li { color: #92400e; }
.summary { color: var(--muted); }
.muted { color: var(--muted); }
footer { margin-top: 26px; font-size: 12.5px; color: var(--muted); }
footer ul { padding-left: 20px; }
.limits { margin-top: 10px; }
@media (max-width: 640px) {
  .hero { flex-direction: column; align-items: flex-start; }
  .verdict { flex-direction: column; align-items: flex-start; }
}
"""

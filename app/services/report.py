from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import re

from flask import render_template

from app.config import get_settings
from app.utils.risk import LEVEL_LABELS, normalize_severity

# 威胁捕获模型 — 8 类（与报告页面需求一致）
RISK_CATEGORIES = [
    {
        "id": "supply_chain",
        "name": "供应链风险",
        "icon": "supply",
        "keywords": ("依赖", "供应链", "package", "requirements", "pip", "npm", "wheel", "vendor"),
    },
    {
        "id": "command_exec",
        "name": "命令执行风险",
        "icon": "terminal",
        "keywords": ("命令", "os.system", "subprocess", "eval", "exec", "shell", "semgrep", "command"),
    },
    {
        "id": "network",
        "name": "网络请求与数据外传",
        "icon": "globe",
        "keywords": ("网络", "http", "request", "urlopen", "socket", "外传", "exfil", "curl", "fetch"),
    },
    {
        "id": "file_ops",
        "name": "文件操作与敏感路径访问",
        "icon": "folder",
        "keywords": ("文件", "/etc", "敏感路径", "path", "open(", "读写", "目录"),
    },
    {
        "id": "prompt_injection",
        "name": "Prompt 注入风险",
        "icon": "prompt",
        "keywords": ("提示注入", "prompt", "injection", "ignore", "instructions", "注入"),
    },
    {
        "id": "remote_script",
        "name": "远程脚本下载执行",
        "icon": "download",
        "keywords": ("远程", "下载", "wget", "powershell", "bash", "script", "execute"),
    },
    {
        "id": "obfuscation",
        "name": "可疑编码/混淆",
        "icon": "code",
        "keywords": ("混淆", "base64", "encode", "decode", "yara", "编码", "obfus"),
    },
    {
        "id": "other",
        "name": "其他安全风险",
        "icon": "shield",
        "keywords": ("恶意", "病毒", "clamav", "密钥", "token", "secret", "私钥", "api key"),
    },
]

ENGINE_LABELS = {
    "clamav": "病毒引擎",
    "regex": "静态引擎",
    "semgrep": "静态引擎",
    "yara": "静态引擎",
    "llm": "AI 引擎",
    "static": "静态引擎",
}


def _severity_counts(findings: list[dict]) -> dict:
    c = Counter(normalize_severity(f.get("severity", "info")) for f in findings)
    return {
        "critical": c.get("critical", 0),
        "high": c.get("high", 0),
        "medium": c.get("medium", 0),
        "low": c.get("low", 0),
        "info": c.get("info", 0),
    }


def _one_line_summary(findings: list[dict], risk_level: str) -> str:
    if not findings:
        return (
            "该 Skill 经 ClamAV、静态规则与 AI 引擎联合分析，未发现明显安全隐患，"
            "整体表现良好，可正常使用。"
        )
    counts = _severity_counts(findings)
    if counts["critical"] or counts["high"]:
        return (
            f"该 Skill 在扫描中发现 {counts['critical'] + counts['high'] + counts['medium'] + counts['low']} "
            f"项安全问题（含 {counts['critical']} 项严重、{counts['high']} 项高危）。"
            "建议在修复高危项并人工复核后再发布或接入生产环境。"
        )
    if counts["medium"]:
        return (
            f"该 Skill 检出 {counts['medium']} 项可疑/中危行为，暂无严重恶意特征。"
            "建议在发布前完成修复与复核。"
        )
    return (
        f"该 Skill 仅存在 {counts['low'] + counts['info']} 项低危或信息类提示，"
        "整体风险可控，可按优先级优化。"
    )


def _finding_text_blob(f: dict) -> str:
    parts = [
        f.get("title") or "",
        f.get("description") or "",
        f.get("location") or "",
        f.get("evidence") or "",
    ]
    return " ".join(parts).lower()


def _categorize_finding(finding: dict) -> str:
    blob = _finding_text_blob(finding)
    best_id = "other"
    best_score = 0
    for cat in RISK_CATEGORIES:
        if cat["id"] == "other":
            continue
        score = sum(1 for kw in cat["keywords"] if kw.lower() in blob)
        if score > best_score:
            best_score = score
            best_id = cat["id"]
    if best_score == 0:
        sev = normalize_severity(finding.get("severity", "info"))
        engine = (finding.get("engine") or "").lower()
        if "clamav" in engine or "恶意" in blob or "病毒" in blob:
            return "other"
        if sev in ("critical", "high"):
            return "other"
    return best_id


def _behavior_status(findings: list[dict]) -> str:
    """safe | suspicious | malicious"""
    if not findings:
        return "safe"
    severities = {normalize_severity(f.get("severity", "info")) for f in findings}
    if severities & {"critical", "high"}:
        return "malicious"
    if severities & {"medium"}:
        return "suspicious"
    if severities & {"low"}:
        return "suspicious"
    return "safe"


BEHAVIOR_LABELS = {
    "safe": "行为安全",
    "suspicious": "行为可疑",
    "malicious": "行为恶意",
}

STATUS_LABELS = {
    "safe": "安全",
    "suspicious": "可疑",
    "malicious": "风险",
}


def _conclusion_for_category(cat_name: str, status: str, findings: list[dict]) -> str:
    if status == "safe":
        return f"✅ {cat_name}：多引擎检测未发现异常行为。"
    if status == "malicious":
        titles = "；".join(f.get("title", "")[:40] for f in findings[:3])
        return f"⚠️ {cat_name}：检出恶意或高危行为（{len(findings)} 项）。{titles}"
    titles = "；".join(f.get("title", "")[:40] for f in findings[:2])
    return f"⚡ {cat_name}：存在可疑行为（{len(findings)} 项），建议复核。{titles}"


def _engines_for_findings(findings: list[dict]) -> list[str]:
    labels = []
    seen = set()
    for f in findings:
        eng = (f.get("engine") or "static").lower()
        label = ENGINE_LABELS.get(eng, "静态引擎")
        if label not in seen:
            seen.add(label)
            labels.append(label)
    if not labels:
        labels = ["静态引擎", "AI 引擎"]
    return labels


def _parse_skill_meta(filename: str) -> tuple[str, str]:
    name = Path(filename).stem
    version = "—"
    m = re.search(r"([\w.-]+)[-_]v?(\d+\.\d+(?:\.\d+)?)", name, re.I)
    if m:
        name, version = m.group(1), m.group(2)
    return name, version


def _trust_label(health_score: int, malicious: int, suspicious: int) -> str:
    if malicious > 0 or health_score < 50:
        return "不可信"
    if suspicious > 0 or health_score < 80:
        return "需关注"
    return "可信"


def build_report_context(scan, findings: list[dict], engines: list[dict]) -> dict:
    counts = _severity_counts(findings)
    malicious_count = counts["critical"] + counts["high"]
    suspicious_count = counts["medium"] + counts["low"]
    total_issues = len([f for f in findings if normalize_severity(f.get("severity")) != "info"])

    risk_score = scan.risk_score or 0
    health_score = max(0, min(100, 100 - int(risk_score)))

    by_category: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        if normalize_severity(f.get("severity")) == "info" and "未发现" in (f.get("title") or ""):
            continue
        cat_id = _categorize_finding(f)
        by_category[cat_id].append(f)

    risk_categories = []
    detailed_analysis = []
    safe_count = 0
    suspicious_cat = 0
    malicious_cat = 0

    for cat in RISK_CATEGORIES:
        cat_findings = by_category.get(cat["id"], [])
        status = _behavior_status(cat_findings)
        if status == "safe":
            safe_count += 1
        elif status == "suspicious":
            suspicious_cat += 1
        else:
            malicious_cat += 1

        risk_categories.append({
            "id": cat["id"],
            "name": cat["name"],
            "icon": cat["icon"],
            "status": status,
            "status_label": STATUS_LABELS[status],
            "finding_count": len(cat_findings),
        })

        log_lines = []
        for f in cat_findings:
            eng = f.get("engine") or "—"
            loc = f.get("location") or "—"
            log_lines.append(
                f"[{normalize_severity(f.get('severity', 'info')).upper()}] "
                f"{f.get('title', '')} @ {loc} ({eng})\n"
                f"  {f.get('description', '')}\n"
                + (f"  证据: {(f.get('evidence') or '')[:300]}\n" if f.get("evidence") else "")
            )

        detailed_analysis.append({
            "id": cat["id"],
            "name": cat["name"],
            "status": status,
            "behavior_label": BEHAVIOR_LABELS[status],
            "engines": _engines_for_findings(cat_findings),
            "conclusion": _conclusion_for_category(cat["name"], status, cat_findings),
            "log_text": "\n".join(log_lines) if log_lines else "（本维度无检测日志）",
            "findings": cat_findings,
        })

    skill_name, skill_version = _parse_skill_meta(scan.filename or "skill")
    sha = scan.sha256 or ""
    hash_short = f"{sha[:12]}…{sha[-8:]}" if len(sha) > 24 else sha or "—"

    health_tone = "good"
    if health_score < 50:
        health_tone = "bad"
    elif health_score < 80:
        health_tone = "warn"

    ring_circumference = 2 * 3.14159 * 70
    ring_offset = ring_circumference * (1 - health_score / 100)

    return {
        "health_score": health_score,
        "health_tone": health_tone,
        "ring_circumference": ring_circumference,
        "ring_offset": ring_offset,
        "stats": {
            "total": total_issues,
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "engines": len(RISK_CATEGORIES),
        },
        "tab_counts": {
            "all": len(RISK_CATEGORIES),
            "malicious": malicious_cat,
            "suspicious": suspicious_cat,
            "safe": safe_count,
        },
        "skill": {
            "name": skill_name,
            "version": skill_version,
            "filename": scan.filename,
            "hash": sha,
            "hash_short": hash_short,
        },
        "trust_label": _trust_label(health_score, malicious_count, suspicious_count),
        "overall_conclusion": _one_line_summary(findings, scan.risk_level),
        "risk_categories": risk_categories,
        "detailed_analysis": detailed_analysis,
        "severity_counts": counts,
        "findings": findings,
    }


def generate_html_report(scan, findings: list[dict], engines: list[dict]) -> Path:
    settings = get_settings()
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    out_path = settings.report_dir / f"report_{scan.id}.html"

    ctx = build_report_context(scan, findings, engines)

    html = render_template(
        "report.html",
        scan=scan,
        engines=engines,
        risk_label=LEVEL_LABELS.get(scan.risk_level, scan.risk_level),
        scan_time=scan.completed_at or scan.created_at or datetime.utcnow(),
        **ctx,
    )

    out_path.write_text(html, encoding="utf-8")
    return out_path

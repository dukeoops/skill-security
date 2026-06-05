import time
from datetime import datetime
from pathlib import Path

from app.extensions import db
from app.models.scan import Scan, ScanFinding
from app.services.clamav import scan_file
from app.services.llm_audit import run_llm_audit
from app.services.report import generate_html_report
from app.services.static_scan import run_static_analysis
from app.services.upload import build_file_tree, cleanup_scan_temp
from app.utils.risk import aggregate_risk, normalize_severity, sort_findings


def _update_progress(scan_id: int, percent: int, message: str) -> None:
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return
    scan.progress = percent
    scan.progress_message = message
    db.session.commit()


def run_scan_pipeline(scan_id: int, archive_path: Path, extract_dir: Path) -> None:
    db.session.remove()
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return

    start = time.perf_counter()
    scan.status = Scan.STATUS_SCANNING
    _update_progress(scan_id, 5, "正在初始化扫描…")

    try:
        scan.file_tree = build_file_tree(extract_dir)
        db.session.commit()

        _update_progress(scan_id, 15, "ClamAV 病毒扫描中…")
        clam = scan_file(archive_path)

        _update_progress(scan_id, 40, "静态规则分析中…")
        static = run_static_analysis(extract_dir)

        _update_progress(scan_id, 65, "LLM 代码审计中…")
        llm = run_llm_audit(extract_dir)

        _update_progress(scan_id, 85, "生成安全报告…")
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return
        all_findings = clam["findings"] + static["findings"] + llm["findings"]
        all_findings = sort_findings(all_findings)
        risk_level, risk_score = aggregate_risk(all_findings)

        scan.engine_summary = {
            "clamav": {k: v for k, v in clam.items() if k != "findings"},
            "static": {k: v for k, v in static.items() if k != "findings"},
            "llm": {k: v for k, v in llm.items() if k != "findings"},
        }
        scan.risk_level = risk_level
        scan.risk_score = risk_score
        scan.scan_duration_ms = int((time.perf_counter() - start) * 1000)

        for f in scan.findings.all():
            db.session.delete(f)
        for item in all_findings:
            db.session.add(ScanFinding(
                scan_id=scan.id,
                title=item.get("title", "未命名发现"),
                severity=normalize_severity(item.get("severity", "info")),
                location=item.get("location"),
                description=item.get("description"),
                evidence=item.get("evidence"),
                impact=item.get("impact"),
                suggestion=item.get("suggestion"),
                engine=item.get("engine"),
            ))

        report_path = generate_html_report(scan, all_findings, [clam, static, llm])
        scan.report_path = str(report_path.resolve())
        scan.status = Scan.STATUS_COMPLETED
        scan.completed_at = datetime.utcnow()
        _update_progress(scan_id, 100, "扫描完成")
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        scan = db.session.get(Scan, scan_id)
        if scan:
            scan.status = Scan.STATUS_FAILED
            scan.error_message = str(exc)
            scan.progress_message = "扫描失败"
            db.session.commit()
    finally:
        cleanup_scan_temp(scan_id)
        db.session.remove()

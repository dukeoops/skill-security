import secrets
import threading
from datetime import datetime, timedelta
from pathlib import Path

from flask import jsonify, request, send_file, current_app
from werkzeug.exceptions import BadRequest, NotFound

from app.api import api_bp
from app.config import get_settings, resolve_report_path
from app.extensions import db
from app.models.scan import Scan, ScanFinding
from app.services.scanner import run_scan_pipeline
from app.services.upload import is_allowed_archive, save_upload
from app.utils.risk import LEVEL_LABELS, sort_findings


def _scan_to_dict(scan: Scan, include_findings: bool = False) -> dict:
    data = {
        "id": scan.id,
        "filename": scan.filename,
        "sha256": scan.sha256,
        "file_size": scan.file_size,
        "risk_level": scan.risk_level,
        "risk_label": LEVEL_LABELS.get(scan.risk_level, scan.risk_level),
        "risk_score": scan.risk_score,
        "status": scan.status,
        "progress": scan.progress,
        "progress_message": scan.progress_message,
        "report_url": f"/api/scans/{scan.id}/report" if scan.report_path else None,
        "share_token": scan.share_token,
        "share_expires_at": scan.share_expires_at.isoformat() if scan.share_expires_at else None,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "scan_duration_ms": scan.scan_duration_ms,
        "error_message": scan.error_message,
    }
    if include_findings:
        findings = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "location": f.location,
                "description": f.description,
                "evidence": f.evidence,
                "impact": f.impact,
                "suggestion": f.suggestion,
                "engine": f.engine,
            }
            for f in scan.findings.order_by(ScanFinding.id).all()
        ]
        data["findings"] = sort_findings(findings)
        data["file_tree"] = scan.file_tree
        data["engine_summary"] = scan.engine_summary
        data["summary_line"] = _summary_from_scan(scan, findings)
    return data


def _summary_from_scan(scan: Scan, findings: list) -> str:
    from app.services.report import _one_line_summary
    return _one_line_summary(findings, scan.risk_level)


@api_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "SkillGuard"})


@api_bp.route("/scans", methods=["POST"])
def create_scan():
    settings = get_settings()
    if "file" not in request.files:
        raise BadRequest("请上传文件")

    file = request.files["file"]
    if not file.filename:
        raise BadRequest("文件名为空")

    if not is_allowed_archive(file.filename):
        raise BadRequest("仅支持 .zip / .tar / .tar.gz / .tgz")

    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > settings.upload_max_bytes:
        raise BadRequest(f"文件超过 {settings.upload_max_mb}MB 限制")

    scan = Scan(
        filename=file.filename,
        file_size=size,
        status=Scan.STATUS_PENDING,
        progress=0,
        progress_message="已接收，排队扫描…",
    )
    db.session.add(scan)
    db.session.commit()

    archive_path, extract_dir, sha = save_upload(file, scan.id)
    scan.sha256 = sha
    scan.temp_path = str(archive_path.parent)
    db.session.commit()

    scan_id = scan.id
    response_data = _scan_to_dict(scan)
    db.session.remove()

    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            try:
                run_scan_pipeline(scan_id, archive_path, extract_dir)
            finally:
                db.session.remove()

    threading.Thread(target=_run, daemon=True).start()

    return jsonify(response_data), 202


@api_bp.route("/scans", methods=["GET"])
def list_scans():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 50)
    pagination = Scan.query.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify({
        "items": [_scan_to_dict(s) for s in pagination.items],
        "total": pagination.total,
        "page": page,
        "per_page": per_page,
    })


@api_bp.route("/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(_scan_to_dict(scan, include_findings=True))


@api_bp.route("/scans/<int:scan_id>/progress", methods=["GET"])
def scan_progress(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({
        "id": scan.id,
        "status": scan.status,
        "progress": scan.progress,
        "progress_message": scan.progress_message,
    })


@api_bp.route("/scans/<int:scan_id>/report", methods=["GET"])
def download_report(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    if not scan.report_path:
        raise NotFound("报告尚未生成")
    report_file = resolve_report_path(scan.report_path)
    if not report_file.exists():
        raise NotFound("报告尚未生成")
    return send_file(
        report_file,
        as_attachment=request.args.get("download") == "1",
        download_name=f"skillguard_report_{scan_id}.html",
        mimetype="text/html",
    )


@api_bp.route("/scans/<int:scan_id>/share", methods=["POST"])
def create_share_link(scan_id: int):
    settings = get_settings()
    scan = Scan.query.get_or_404(scan_id)
    if scan.status != Scan.STATUS_COMPLETED:
        raise BadRequest("扫描未完成，无法分享")
    scan.share_token = secrets.token_urlsafe(32)
    scan.share_expires_at = datetime.utcnow() + timedelta(hours=settings.share_link_expire_hours)
    db.session.commit()
    return jsonify({
        "share_token": scan.share_token,
        "share_url": f"/share/{scan.share_token}",
        "expires_at": scan.share_expires_at.isoformat(),
    })


@api_bp.route("/share/<token>", methods=["GET"])
def get_shared_scan(token: str):
    scan = Scan.query.filter_by(share_token=token).first_or_404()
    if scan.share_expires_at and scan.share_expires_at < datetime.utcnow():
        raise NotFound("分享链接已过期")
    return jsonify(_scan_to_dict(scan, include_findings=True))

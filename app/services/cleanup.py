import shutil
from datetime import datetime, timedelta
from pathlib import Path

from app.config import get_settings
from app.extensions import db
from app.models.scan import Scan
from app.services.upload import cleanup_scan_temp


def cleanup_expired_temp_dirs() -> int:
    settings = get_settings()
    if not settings.temp_dir.exists():
        return 0
    cutoff = datetime.utcnow() - timedelta(minutes=settings.temp_cleanup_minutes)
    removed = 0
    for scan in Scan.query.filter(Scan.created_at < cutoff).all():
        if scan.temp_path:
            p = Path(scan.temp_path)
            if p.exists():
                shutil.rmtree(p, ignore_errors=True)
                removed += 1
        cleanup_scan_temp(scan.id)
    return removed


def cleanup_expired_share_links() -> int:
    settings = get_settings()
    now = datetime.utcnow()
    expired = Scan.query.filter(
        Scan.share_expires_at.isnot(None),
        Scan.share_expires_at < now,
    ).all()
    for scan in expired:
        scan.share_token = None
        scan.share_expires_at = None
    if expired:
        db.session.commit()
    return len(expired)

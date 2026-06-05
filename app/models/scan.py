from datetime import datetime

from app.extensions import db


class Scan(db.Model):
    __tablename__ = "scans"

    STATUS_PENDING = "pending"
    STATUS_SCANNING = "scanning"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    filename = db.Column(db.String(512), nullable=False)
    sha256 = db.Column(db.String(64), nullable=True, index=True)
    file_size = db.Column(db.BigInteger, nullable=True)
    risk_level = db.Column(db.String(32), default="safe")
    risk_score = db.Column(db.Integer, default=0)
    report_path = db.Column(db.String(1024), nullable=True)
    status = db.Column(db.String(32), default=STATUS_PENDING, index=True)
    progress = db.Column(db.Integer, default=0)
    progress_message = db.Column(db.String(256), default="等待扫描")
    share_token = db.Column(db.String(64), unique=True, nullable=True, index=True)
    share_expires_at = db.Column(db.DateTime, nullable=True)
    temp_path = db.Column(db.String(1024), nullable=True)
    engine_summary = db.Column(db.JSON, nullable=True)
    file_tree = db.Column(db.JSON, nullable=True)
    scan_duration_ms = db.Column(db.Integer, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", back_populates="scans")
    findings = db.relationship(
        "ScanFinding",
        back_populates="scan",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )


class ScanFinding(db.Model):
    __tablename__ = "scan_findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    title = db.Column(db.String(512), nullable=False)
    severity = db.Column(db.String(32), nullable=False, index=True)
    location = db.Column(db.String(1024), nullable=True)
    description = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    impact = db.Column(db.Text, nullable=True)
    suggestion = db.Column(db.Text, nullable=True)
    engine = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    scan = db.relationship("Scan", back_populates="findings")


class SystemConfig(db.Model):
    __tablename__ = "system_config"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(128), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

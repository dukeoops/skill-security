from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, send_from_directory

from app.config import get_settings
from app.extensions import db, migrate


def create_app() -> Flask:
    settings = get_settings()
    base = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        template_folder=str(base / "templates"),
        static_folder=str(base / "static"),
    )
    app.config["SECRET_KEY"] = settings.secret_key
    app.config["SQLALCHEMY_DATABASE_URI"] = settings.database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
        "pool_size": 10,
        "max_overflow": 20,
    }
    app.config["MAX_CONTENT_LENGTH"] = settings.upload_max_bytes

    settings.temp_dir.mkdir(parents=True, exist_ok=True)
    settings.report_dir.mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)

    @app.teardown_appcontext
    def _remove_session(_exc=None):
        db.session.remove()

    from app.api import api_bp
    app.register_blueprint(api_bp)

    @app.route("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/history")
    def history_page():
        return send_from_directory(app.static_folder, "history.html")

    @app.route("/report/<int:scan_id>")
    def report_view(scan_id: int):
        return send_from_directory(app.static_folder, "report-view.html")

    @app.route("/share/<token>")
    def share_page(token: str):
        return send_from_directory(app.static_folder, "share.html")

    @app.errorhandler(400)
    @app.errorhandler(404)
    def handle_http(err):
        from flask import jsonify
        code = err.code if hasattr(err, "code") else 500
        return jsonify({"error": getattr(err, "description", str(err))}), code

    @app.errorhandler(500)
    def handle_500(err):
        import logging
        from flask import jsonify
        logging.exception("Internal error: %s", err)
        db.session.rollback()
        db.session.remove()
        return jsonify({"error": "服务器内部错误，请稍后重试"}), 500

    if not app.debug or app.config.get("WERKZEUG_RUN_MAIN"):
        _start_scheduler(app)

    return app


def _start_scheduler(app: Flask) -> None:
    scheduler = BackgroundScheduler(daemon=True)

    def _cleanup_job():
        with app.app_context():
            try:
                from app.services.cleanup import cleanup_expired_temp_dirs, cleanup_expired_share_links
                cleanup_expired_temp_dirs()
                cleanup_expired_share_links()
            finally:
                db.session.remove()

    scheduler.add_job(_cleanup_job, "interval", minutes=10, id="cleanup")
    if not scheduler.running:
        scheduler.start()

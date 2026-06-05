"""初始化数据库表（开发用）"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app
from app.extensions import db

app = create_app()
with app.app_context():
    db.create_all()
    print("数据库表已创建")

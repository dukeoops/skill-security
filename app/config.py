from pathlib import Path
from functools import lru_cache
from typing import Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# 项目根目录（app 的上一级），避免相对路径随进程 cwd 变化
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def resolve_data_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def resolve_report_path(stored: str) -> Path:
    """解析数据库中的报告路径（兼容历史相对路径）。"""
    p = Path(stored)
    if p.is_absolute():
        if p.exists():
            return p
        canonical = get_settings().report_dir / p.name
        if canonical.exists():
            return canonical
        return p
    return resolve_data_path(p)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    flask_env: str = "development"
    secret_key: str = "dev-secret-change-in-production"

    database_url: str = (
        "mysql+pymysql://skillguard:skillguard@127.0.0.1:3306/skillguard?charset=utf8mb4"
    )

    temp_dir: Path = Path("data/temp")
    report_dir: Path = Path("data/reports")
    upload_max_mb: int = 200
    temp_cleanup_minutes: int = 30

    clamav_api_url: str = ""
    clamav_api_token: str = ""
    clamav_enabled: bool = True
    clamav_mock: bool = False

    llm_provider: str = "openai"
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_enabled: bool = True
    llm_mock: bool = False
    llm_timeout: int = 120
    llm_chunk_size: int = 8000

    semgrep_enabled: bool = True
    yara_enabled: bool = True
    semgrep_mock: bool = False

    share_link_expire_hours: int = 72

    allowed_extensions: tuple[str, ...] = (".zip", ".tar", ".tar.gz", ".tgz")

    @model_validator(mode="after")
    def _normalize_data_paths(self) -> Self:
        self.temp_dir = resolve_data_path(self.temp_dir)
        self.report_dir = resolve_data_path(self.report_dir)
        return self

    @property
    def upload_max_bytes(self) -> int:
        return self.upload_max_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()

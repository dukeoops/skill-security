import hashlib
import os
import shutil
import tarfile
import zipfile
from pathlib import Path

from werkzeug.utils import secure_filename

from app.config import get_settings


def is_allowed_archive(filename: str) -> bool:
    name = filename.lower()
    settings = get_settings()
    return any(name.endswith(ext) for ext in settings.allowed_extensions)


def extract_archive(archive_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = archive_path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dest_dir)
    elif name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(dest_dir)
    elif name.endswith(".tar"):
        with tarfile.open(archive_path, "r:") as tf:
            tf.extractall(dest_dir)
    else:
        raise ValueError("不支持的压缩格式")


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_file_tree(root: Path, base: Path | None = None) -> list[dict]:
    base = base or root
    nodes = []
    try:
        entries = sorted(root.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except PermissionError:
        return nodes
    for entry in entries:
        rel = str(entry.relative_to(base)).replace("\\", "/")
        if entry.is_dir():
            nodes.append({
                "name": entry.name,
                "path": rel,
                "type": "dir",
                "children": build_file_tree(entry, base),
            })
        else:
            try:
                size = entry.stat().st_size
            except OSError:
                size = 0
            nodes.append({
                "name": entry.name,
                "path": rel,
                "type": "file",
                "size": size,
            })
    return nodes


def iter_code_files(root: Path, max_files: int = 200) -> list[Path]:
    code_ext = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml",
        ".md", ".sh", ".bash", ".ps1", ".go", ".rs", ".java", ".rb",
        ".php", ".html", ".css", ".vue", ".sql", ".env", ".toml",
    }
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in code_ext or fn in ("Dockerfile", "Makefile"):
                results.append(p)
                if len(results) >= max_files:
                    return results
    return results


def save_upload(file_storage, scan_id: int) -> tuple[Path, Path, str]:
    settings = get_settings()
    safe_name = secure_filename(file_storage.filename or "upload.zip")
    work_dir = settings.temp_dir / str(scan_id)
    work_dir.mkdir(parents=True, exist_ok=True)
    archive_path = work_dir / safe_name
    file_storage.save(archive_path)
    sha = compute_sha256(archive_path)
    extract_dir = work_dir / "extracted"
    extract_archive(archive_path, extract_dir)
    return archive_path, extract_dir, sha


def cleanup_scan_temp(scan_id: int) -> None:
    settings = get_settings()
    work_dir = settings.temp_dir / str(scan_id)
    if work_dir.exists():
        shutil.rmtree(work_dir, ignore_errors=True)

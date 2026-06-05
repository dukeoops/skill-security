import time
from pathlib import Path

import requests

from app.config import get_settings


def scan_file(path: Path) -> dict:
    settings = get_settings()
    start = time.perf_counter()

    if not settings.clamav_enabled:
        return {
            "engine": "clamav",
            "status": "skipped",
            "findings": [],
            "duration_ms": 0,
            "message": "ClamAV 已禁用",
        }

    if settings.clamav_mock or not settings.clamav_api_url:
        return {
            "engine": "clamav",
            "status": "ok",
            "findings": [],
            "duration_ms": int((time.perf_counter() - start) * 1000),
            "message": "模拟扫描通过（未配置 ClamAV API）",
        }

    headers = {"Authorization": f"Bearer {settings.clamav_api_token}"}
    try:
        with open(path, "rb") as f:
            resp = requests.post(
                settings.clamav_api_url,
                files={"file": (path.name, f)},
                headers=headers,
                timeout=120,
            )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        return {
            "engine": "clamav",
            "status": "error",
            "findings": [{
                "title": "ClamAV API 调用失败",
                "severity": "medium",
                "location": str(path),
                "description": str(exc),
                "evidence": "",
                "impact": "无法完成病毒扫描",
                "suggestion": "检查 ClamAV API 地址与 Token 配置",
                "engine": "clamav",
            }],
            "duration_ms": int((time.perf_counter() - start) * 1000),
            "message": str(exc),
        }

    findings = []
    infected = data.get("infected") or data.get("is_infected") or False
    signature = data.get("signature") or data.get("virus_name")
    if infected or signature:
        findings.append({
            "title": f"检测到恶意软件: {signature or '未知'}",
            "severity": "critical",
            "location": path.name,
            "description": f"ClamAV 检出: {signature}",
            "evidence": str(data),
            "impact": "压缩包可能包含恶意代码，禁止分发",
            "suggestion": "删除文件并使用干净来源重新打包",
            "engine": "clamav",
        })

    return {
        "engine": "clamav",
        "status": "infected" if findings else "ok",
        "findings": findings,
        "duration_ms": int((time.perf_counter() - start) * 1000),
        "message": "检出威胁" if findings else "未检出病毒",
    }

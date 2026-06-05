import json
import re
import time
from pathlib import Path

from app.config import get_settings
from app.services.upload import iter_code_files

AUDIT_SYSTEM = """你是 AI Skill 安全审计专家。分析代码片段，检测：
1. 提示注入（prompt injection）
2. 数据外泄（exfiltration）
3. 权限滥用（privilege escalation）
4. 恶意网络/文件操作

以 JSON 数组返回发现项，每项字段：
title, severity(critical|high|medium|low|info), location, description, evidence, impact, suggestion
无问题时返回空数组 []。只输出 JSON，不要 markdown。"""

# 典型 API / 模型报错关键词（用于识别非审计内容）
_ERROR_MARKERS = (
    "error", "exception", "traceback", "failed", "failure",
    "model not found", "does not exist", "connection refused", "connection error",
    "timeout", "timed out", "rate limit", "unauthorized", "forbidden",
    "invalid api key", "api key", "status code", "http error",
    "internal server error", "bad gateway", "service unavailable",
    "no such file", "not found", "ollama", "openai", "apierror",
    "无法连接", "连接失败", "请求失败", "模型不存在", "调用失败",
)

_HTTP_STATUS_RE = re.compile(r"\b[45]\d{2}\b")


def _chunk_text(text: str, size: int) -> list[str]:
    if len(text) <= size:
        return [text]
    chunks = []
    start = 0
    while start < len(text):
        chunks.append(text[start : start + size])
        start += size
    return chunks


def _strip_markdown_fence(content: str) -> str:
    text = content.strip()
    if not text.startswith("```"):
        return text
    lines = text.split("\n")
    if lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()
    return "\n".join(lines[1:]).strip()


def _extract_api_error_from_json(content: str) -> str | None:
    """识别 OpenAI/Ollama 等返回的 error JSON 对象。"""
    text = _strip_markdown_fence(content)
    if not text.startswith("{"):
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    if "error" in obj:
        err = obj["error"]
        if isinstance(err, dict):
            return err.get("message") or err.get("detail") or json.dumps(err, ensure_ascii=False)
        return str(err)
    if obj.get("object") == "error" or obj.get("type") == "error":
        return obj.get("message") or json.dumps(obj, ensure_ascii=False)
    return None


def _looks_like_plain_error(content: str) -> bool:
    text = _strip_markdown_fence(content)
    if not text:
        return True
    lower = text.lower()
    if lower.startswith(("error", "exception", "traceback", "failed:", "failure:")):
        return True
    if _HTTP_STATUS_RE.search(text) and any(m in lower for m in ("error", "status", "http", "请求")):
        return True
    return any(marker in lower for marker in _ERROR_MARKERS)


def _is_empty_audit_payload(content: str) -> bool:
    """判断是否为合法的「无发现问题」空结果。"""
    text = _strip_markdown_fence(content)
    if text in ("[]", "{}"):
        return True
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("[")
        end = text.rfind("]")
        if start < 0 or end <= start:
            return False
        try:
            data = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return False
    if isinstance(data, list):
        return len(data) == 0
    if isinstance(data, dict):
        items = data.get("findings", data.get("items"))
        return isinstance(items, list) and len(items) == 0
    return False


def _parse_llm_json(content: str) -> list[dict]:
    content = _strip_markdown_fence(content)
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        start = content.find("[")
        end = content.rfind("]")
        if start >= 0 and end > start:
            try:
                data = json.loads(content[start : end + 1])
            except json.JSONDecodeError:
                return []
        else:
            return []
    if isinstance(data, dict):
        data = data.get("findings", data.get("items", []))
    if not isinstance(data, list):
        return []
    results = []
    for item in data:
        if not isinstance(item, dict) or not item.get("title"):
            continue
        item["engine"] = "llm"
        results.append(item)
    return results


def _classify_llm_response(content: str) -> tuple[list[dict], str | None]:
    """
    将 LLM 原始返回分为审计发现或调用错误。
    返回 (findings, error_message)；error_message 非空表示不应计入安全发现。
    """
    api_err = _extract_api_error_from_json(content)
    if api_err:
        return [], api_err

    if _looks_like_plain_error(content):
        text = _strip_markdown_fence(content).strip()
        return [], text[:800] if text else "LLM 返回异常空内容"

    findings = _parse_llm_json(content)
    if findings:
        return findings, None

    if _is_empty_audit_payload(content):
        return [], None

    preview = _strip_markdown_fence(content).strip()[:200]
    return [], f"LLM 返回无法解析为审计 JSON（非安全问题）: {preview}"


def _format_api_error(exc: Exception) -> str:
    """提取 API 异常中的可读信息，避免冗长堆栈进入报告。"""
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if isinstance(err, str):
            return err
    message = getattr(exc, "message", None)
    if message and str(message) != str(exc):
        return str(message)
    text = str(exc).strip()
    if len(text) > 500:
        return text[:500] + "…"
    return text or exc.__class__.__name__


def _call_openai(prompt: str) -> str:
    settings = get_settings()
    from openai import OpenAI

    client = OpenAI(api_key=settings.llm_api_key or "sk-mock", base_url=settings.llm_base_url)
    resp = client.chat.completions.create(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": AUDIT_SYSTEM},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        timeout=settings.llm_timeout,
    )
    if not resp.choices:
        raise RuntimeError("LLM 返回无 choices")
    return resp.choices[0].message.content or "[]"


def _record_llm_failure(
    raw_responses: list[dict],
    errors: list[dict],
    *,
    file: str,
    chunk_index: int,
    message: str,
) -> None:
    errors.append({"file": file, "chunk_index": chunk_index, "message": message})
    raw_responses.append({
        "file": file,
        "chunk_index": chunk_index,
        "failed": True,
        "error": message,
        "raw": message,
    })


def _build_llm_result(
    *,
    findings: list[dict],
    errors: list[dict],
    raw_responses: list[dict],
    duration_ms: int,
) -> dict:
    if errors and not findings:
        status = "error"
        first = errors[0]["message"]
        message = f"LLM 审计失败（{len(errors)} 次调用异常）: {first[:120]}"
    elif errors:
        status = "partial"
        message = (
            f"LLM 审计部分完成：{len(findings)} 项发现，"
            f"{len(errors)} 次调用失败（详见报告附录）"
        )
    else:
        status = "ok"
        message = f"LLM 审计完成，发现 {len(findings)} 项"

    return {
        "engine": "llm",
        "status": status,
        "findings": findings,
        "errors": errors,
        "duration_ms": duration_ms,
        "message": message,
        "raw_responses": raw_responses,
    }


def _mock_audit(files: list[Path], root: Path) -> list[dict]:
    findings = []
    for fp in files[:5]:
        rel = str(fp.relative_to(root)).replace("\\", "/")
        if fp.suffix == ".py":
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "subprocess" in text or "os.system" in text:
                findings.append({
                    "title": "LLM 审计：可疑子进程调用",
                    "severity": "medium",
                    "location": rel,
                    "description": "代码中存在子进程或系统命令调用，需确认是否为 Skill 必要功能",
                    "evidence": "检测到 subprocess 或 os.system 相关调用（模拟审计）",
                    "impact": "可能被用于执行任意系统命令",
                    "suggestion": "限制命令白名单，避免用户可控参数传入 shell",
                    "engine": "llm",
                })
    if not findings:
        findings.append({
            "title": "LLM 审计：未发现高危模式",
            "severity": "info",
            "location": "全局",
            "description": "模拟 LLM 审计完成，未检出典型高危模式",
            "evidence": "",
            "impact": "无",
            "suggestion": "生产环境请配置真实 LLM API 以获得深度审计",
            "engine": "llm",
        })
    return findings


def run_llm_audit(extract_dir: Path) -> dict:
    settings = get_settings()
    start = time.perf_counter()
    files = iter_code_files(extract_dir, max_files=30)

    if not settings.llm_enabled:
        return {
            "engine": "llm",
            "status": "skipped",
            "findings": [],
            "errors": [],
            "duration_ms": 0,
            "message": "LLM 审计已禁用",
            "raw_responses": [],
        }

    if settings.llm_mock or not settings.llm_api_key:
        findings = _mock_audit(files, extract_dir)
        return {
            "engine": "llm",
            "status": "ok",
            "findings": findings,
            "errors": [],
            "duration_ms": int((time.perf_counter() - start) * 1000),
            "message": "模拟 LLM 审计完成",
            "raw_responses": [
                {
                    "file": "(模拟模式)",
                    "chunk_index": 0,
                    "raw": json.dumps(findings, ensure_ascii=False, indent=2),
                    "note": "未调用真实 LLM API，以上为本地模拟审计结果",
                }
            ],
        }

    all_findings: list[dict] = []
    raw_responses: list[dict] = []
    errors: list[dict] = []

    for fp in files[:15]:
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(fp.relative_to(extract_dir)).replace("\\", "/")
        for chunk_idx, chunk in enumerate(_chunk_text(text, settings.llm_chunk_size)[:2]):
            prompt = f"文件: {rel}\n\n```\n{chunk[:6000]}\n```"
            try:
                raw = _call_openai(prompt)
            except Exception as exc:
                _record_llm_failure(
                    raw_responses,
                    errors,
                    file=rel,
                    chunk_index=chunk_idx,
                    message=_format_api_error(exc),
                )
                continue

            findings, err = _classify_llm_response(raw)
            entry: dict = {
                "file": rel,
                "chunk_index": chunk_idx,
                "raw": raw,
            }
            if err:
                entry["failed"] = True
                entry["error"] = err
                errors.append({"file": rel, "chunk_index": chunk_idx, "message": err})
            else:
                all_findings.extend(findings)
            raw_responses.append(entry)

    return _build_llm_result(
        findings=all_findings,
        errors=errors,
        raw_responses=raw_responses,
        duration_ms=int((time.perf_counter() - start) * 1000),
    )

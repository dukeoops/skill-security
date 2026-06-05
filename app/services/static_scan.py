import json
import re
import subprocess
import time
from pathlib import Path

from app.config import get_settings
from app.services.upload import iter_code_files

# (正则, 标题, 严重级别 critical|high|medium|low)
REGEX_RULES: list[tuple[str, str, str]] = [
    # --- 密钥与敏感信息 ---
    (r"(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{8,}", "硬编码密钥或令牌", "high"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI API Key 泄露", "high"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key 泄露", "high"),
    (r"ghp_[A-Za-z0-9]{36,}", "GitHub Personal Access Token 泄露", "high"),
    (r"gho_[A-Za-z0-9]{36,}", "GitHub OAuth Token 泄露", "high"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack Token 泄露", "high"),
    (r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer 令牌硬编码", "high"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "私钥文件内容", "high"),
    (r"(?i)(jwt[_-]?secret|signing[_-]?key|encryption[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}", "签名/加密密钥硬编码", "high"),

    # --- 提示注入 ---
    (r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions", "提示注入：忽略先前指令", "high"),
    (r"(?i)system\s*:\s*you\s+are\s+now", "提示注入：角色覆盖", "high"),
    (r"(?i)disregard\s+(your|the)\s+(rules|guidelines|safety)", "提示注入：无视规则", "high"),
    (r"(?i)forget\s+(everything|all)\s+(you\s+)?(know|learned|above)", "提示注入：遗忘上下文", "high"),
    (r"(?i)new\s+instructions?\s*:", "提示注入：覆盖新指令", "high"),
    (r"(?i)(jailbreak|DAN\s+mode|developer\s+mode\s+enabled)", "提示注入：越狱模式", "high"),
    (r"(忽略|无视|绕过).{0,12}(指令|规则|安全|限制)", "提示注入：中文绕过指令", "high"),
    (r"(?i)override\s+(system|safety)\s+(prompt|rules)", "提示注入：覆盖系统提示", "high"),

    # --- 高危命令执行与反序列化 ---
    (r"\bos\.system\s*\(", "命令执行 os.system", "high"),
    (r"\bos\.popen\s*\(", "命令执行 os.popen", "high"),
    (r"\bsubprocess\.(call|Popen|run)\s*\(", "子进程调用", "medium"),
    (r"subprocess\.[^(]+\([^)]*shell\s*=\s*True", "子进程 shell=True", "high"),
    (r"\beval\s*\(", "动态执行 eval", "high"),
    (r"\bexec\s*\(", "动态执行 exec", "high"),
    (r"\bcompile\s*\([^)]+\)\s*,\s*['\"]<", "动态编译执行", "high"),
    (r"\bpickle\.loads?\s*\(", "不安全反序列化 pickle", "high"),
    (r"\bmarshal\.loads?\s*\(", "不安全反序列化 marshal", "high"),
    (r"\b__import__\s*\(", "动态模块导入 __import__", "medium"),
    (r"\bctypes\.(CDLL|windll|dll)", "原生库加载 ctypes", "high"),
    (r"child_process\.(exec|execSync|spawn)\s*\(", "Node 子进程执行", "high"),
    (r"(?i)Invoke-Expression|IEX\s*\(", "PowerShell 动态执行", "high"),
    (r"(?i)Start-Process\s+.*powershell", "PowerShell 启动进程", "medium"),
    (r"curl\s+[^\n|]{0,200}\|\s*(ba)?sh", "curl 管道到 shell", "high"),
    (r"wget\s+[^\n|]{0,200}\|\s*(ba)?sh", "wget 管道到 shell", "high"),
    (r"(?i)rm\s+-rf\s+/(\s|$|')", "危险删除 rm -rf /", "critical"),
    (r"chmod\s+777\s+", "过度宽松权限 chmod 777", "medium"),

    # --- 网络与外泄 ---
    (r"requests\.(get|post|put|patch|delete)\s*\(", "HTTP 请求 requests", "medium"),
    (r"urllib\.request\.urlopen\s*\(", "外部 URL 访问 urllib", "medium"),
    (r"httpx\.(get|post|AsyncClient)", "HTTP 请求 httpx", "medium"),
    (r"aiohttp\.ClientSession", "异步 HTTP 客户端 aiohttp", "medium"),
    (r"socket\.(create_connection|connect)\s*\(", "网络 socket 连接", "medium"),
    (r"fetch\s*\(\s*['\"]https?://", "前端 fetch 外部 URL", "medium"),
    (r"axios\.(get|post)\s*\(", "axios HTTP 请求", "medium"),
    (r"XMLHttpRequest\s*\(", "XMLHttpRequest 请求", "low"),
    (r"hooks\.slack\.com/services/", "Slack Webhook 外发", "high"),
    (r"discord(?:app)?\.com/api/webhooks/", "Discord Webhook 外发", "high"),
    (r"(?i)(exfiltrat|send.*(?:credentials|secrets|tokens).*http)", "疑似数据外传描述", "medium"),

    # --- 敏感路径与文件操作 ---
    (r"open\s*\([^)]*['\"]\/etc\/(passwd|shadow|hosts)", "访问系统敏感文件 /etc", "high"),
    (r"open\s*\([^)]*['\"](?:~\/|\$HOME\/)\.ssh\/", "访问 SSH 私钥路径", "high"),
    (r"['\"](?:/etc/passwd|/etc/shadow|~/.ssh/id_rsa)['\"]", "引用敏感系统路径", "high"),
    (r"shutil\.rmtree\s*\(", "递归删除目录 shutil.rmtree", "medium"),
    (r"fs\.(?:writeFile|appendFile|createWriteStream)\s*\(", "Node 文件写入", "low"),

    # --- 供应链与远程安装 ---
    (r"pip\s+install\s+[^\n]*https?://", "pip 从远程 URL 安装", "high"),
    (r"pip\s+install\s+[^\n]*--index-url", "pip 自定义索引源", "medium"),
    (r"npm\s+install\s+[^\n]*https?://", "npm 从远程 URL 安装", "high"),
    (r"npm\s+install\s+-g\s+", "npm 全局安装", "medium"),
    (r"curl\s+[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh", "curl 下载并执行脚本", "high"),
    (r"wget\s+-O\s+[^\n]+\s+&&\s*chmod", "wget 下载后赋权执行", "high"),

    # --- 混淆与编码执行 ---
    (r"base64\.b64decode\s*\([^)]+\).*?(?:exec|eval)\s*\(", "Base64 解码后执行", "high"),
    (r"(?:exec|eval)\s*\(\s*base64\.b64decode", "对 Base64 内容动态执行", "high"),
    (r"zlib\.decompress\s*\([^)]+\).*?(?:exec|eval)", "zlib 解压后执行", "high"),
    (r"codecs\.decode\s*\([^)]*['\"]rot", "ROT 等编码混淆", "medium"),
    (r"fromhex\s*\([^)]+\).*?(?:exec|eval)", "十六进制载荷执行", "high"),
    (r"(?i)atob\s*\([^)]+\).*eval", "浏览器 atob 后 eval", "high"),

    # --- 环境变量与配置读取 ---
    (r"load_dotenv\s*\(", "加载 .env 环境变量", "low"),
    (r"dotenv\.config\s*\(", "dotenv 配置加载", "low"),
    (r"os\.environ\.get\s*\(\s*['\"](?:KEY|TOKEN|SECRET|PASSWORD)", "读取敏感环境变量名", "medium"),
]

SEMGREP_RULES_YAML = """\
rules:
  - id: skill-exec-os-system
    pattern: os.system(...)
    message: Python os.system 命令执行
    languages: [python]
    severity: WARNING

  - id: skill-exec-subprocess
    patterns:
      - pattern: subprocess.run(...)
      - pattern: subprocess.call(...)
      - pattern: subprocess.Popen(...)
    message: Python subprocess 子进程调用
    languages: [python]
    severity: WARNING

  - id: skill-subprocess-shell
    patterns:
      - pattern: subprocess.run(..., shell=True, ...)
      - pattern: subprocess.call(..., shell=True, ...)
      - pattern: subprocess.Popen(..., shell=True, ...)
    message: subprocess 使用 shell=True
    languages: [python]
    severity: ERROR

  - id: skill-pickle-loads
    pattern: pickle.loads(...)
    message: 不安全 pickle 反序列化
    languages: [python]
    severity: ERROR

  - id: skill-eval-exec
    patterns:
      - pattern: eval(...)
      - pattern: exec(...)
    message: Python 动态执行 eval/exec
    languages: [python]
    severity: ERROR

  - id: skill-js-child-process
    patterns:
      - pattern: require('child_process')
      - pattern: require("child_process")
    message: Node.js child_process 模块引用
    languages: [javascript, typescript]
    severity: WARNING

  - id: skill-js-exec-sync
    pattern: |
      require('child_process').execSync(...)
    message: Node.js execSync 同步命令执行
    languages: [javascript, typescript]
    severity: ERROR
"""

YARA_RULES_SOURCE = r"""
rule skill_pipe_to_shell {
    meta:
        description = "curl/wget 管道到 shell"
    strings:
        $curl = "curl" nocase
        $wget = "wget" nocase
        $pipe = "|" ascii
        $bash = "bash" nocase
        $sh = "| sh" nocase
    condition:
        ($curl or $wget) and $pipe and ($bash or $sh)
}

rule skill_powershell_abuse {
    meta:
        description = "PowerShell 可疑执行组合"
    strings:
        $iex = "Invoke-Expression" nocase
        $iex2 = "IEX(" nocase
        $dl = "DownloadString" nocase
        $enc = "-EncodedCommand" nocase
    condition:
        2 of them
}

rule skill_obfuscation_exec {
    meta:
        description = "编码/混淆后执行"
    strings:
        $b64 = "base64" nocase
        $b64d = "b64decode" nocase
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $atob = "atob(" nocase
    condition:
        ($b64 or $b64d or $atob) and ($eval or $exec)
}

rule skill_webhook_exfil {
    meta:
        description = "常见 Webhook 外传端点"
    strings:
        $slack = "hooks.slack.com/services/" nocase
        $discord = "discord.com/api/webhooks" nocase
        $discord2 = "discordapp.com/api/webhooks" nocase
    condition:
        any of them
}

rule skill_remote_script {
    meta:
        description = "远程脚本下载执行特征"
    strings:
        $curl = "curl" nocase
        $wget = "wget" nocase
        $bash = "bash" nocase
        $ps1 = ".ps1" nocase
        $chmod = "chmod +x" nocase
    condition:
        ($curl or $wget) and ($bash or $ps1 or $chmod)
}

rule skill_suspicious_combo {
    meta:
        description = "多可疑字符串组合（启发式）"
    strings:
        $a = "curl" nocase
        $b = "/bin/bash" nocase
        $c = "powershell" nocase
        $d = "base64_decode" nocase
        $e = "pickle.loads" nocase
    condition:
        2 of them
}
"""

_IMPACT_BY_SEVERITY = {
    "critical": "可能导致系统被破坏或完全失控",
    "high": "可能导致凭证泄露、远程代码执行或权限提升",
    "medium": "存在可疑网络、文件或安装行为，需人工复核",
    "low": "低风险提示，建议确认是否为必要功能",
}

_SUGGESTION_BY_SEVERITY = {
    "critical": "立即移除或隔离该代码，禁止在生产环境使用",
    "high": "移除敏感硬编码，禁用危险 API，改用安全替代方案",
    "medium": "审查调用目的与参数来源，限制网络与文件访问范围",
    "low": "确认是否为 Skill 必要逻辑，避免读取无关敏感配置",
}


def _regex_scan_file(path: Path, root: Path) -> list[dict]:
    findings = []
    rel = str(path.relative_to(root)).replace("\\", "/")
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for pattern, desc, severity in REGEX_RULES:
        for m in re.finditer(pattern, text):
            line_no = text[: m.start()].count("\n") + 1
            snippet = text[max(0, m.start() - 40) : m.end() + 40].replace("\n", " ")
            findings.append({
                "title": desc,
                "severity": severity,
                "location": f"{rel}:{line_no}",
                "description": f"正则规则匹配: {desc}",
                "evidence": snippet[:500],
                "impact": _IMPACT_BY_SEVERITY.get(severity, _IMPACT_BY_SEVERITY["medium"]),
                "suggestion": _SUGGESTION_BY_SEVERITY.get(severity, _SUGGESTION_BY_SEVERITY["medium"]),
                "engine": "regex",
            })
    return findings


def _run_semgrep(root: Path) -> list[dict]:
    settings = get_settings()
    if not settings.semgrep_enabled:
        return []

    if settings.semgrep_mock:
        return []

    rules_path = root.parent / "_semgrep_rules.yaml"
    rules_path.write_text(SEMGREP_RULES_YAML, encoding="utf-8")
    try:
        proc = subprocess.run(
            ["semgrep", "--config", str(rules_path), str(root), "--json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if proc.returncode not in (0, 1) or not proc.stdout.strip():
            return []
        data = json.loads(proc.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return []
    finally:
        if rules_path.exists():
            rules_path.unlink(missing_ok=True)

    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        sev = "medium"
        if extra.get("severity") in ("ERROR", "HIGH"):
            sev = "high"
        findings.append({
            "title": extra.get("message", "Semgrep 规则命中"),
            "severity": sev,
            "location": f"{r.get('path', '')}:{r.get('start', {}).get('line', 0)}",
            "description": extra.get("message", ""),
            "evidence": extra.get("lines", "")[:500],
            "impact": "静态分析发现潜在安全问题",
            "suggestion": "根据 Semgrep 建议修复代码",
            "engine": "semgrep",
        })
    return findings


def _run_yara(root: Path) -> list[dict]:
    settings = get_settings()
    if not settings.yara_enabled:
        return []
    try:
        import yara
    except ImportError:
        return []

    try:
        rules = yara.compile(source=YARA_RULES_SOURCE)
    except Exception:
        return []

    findings = []
    seen: set[tuple[str, str]] = set()
    for fp in iter_code_files(root, max_files=100):
        try:
            matches = rules.match(str(fp))
        except Exception:
            continue
        if not matches:
            continue
        rel = str(fp.relative_to(root)).replace("\\", "/")
        for match in matches:
            key = (rel, match.rule)
            if key in seen:
                continue
            seen.add(key)
            desc = match.meta.get("description", match.rule) if match.meta else match.rule
            matched = ", ".join(str(s) for s in match.strings[:4])
            findings.append({
                "title": f"YARA 规则命中: {match.rule}",
                "severity": "high" if match.rule in (
                    "skill_pipe_to_shell", "skill_webhook_exfil", "skill_obfuscation_exec"
                ) else "medium",
                "location": rel,
                "description": f"{desc}；匹配: {matched[:200]}",
                "evidence": matched[:500],
                "impact": "文件包含可疑脚本特征组合",
                "suggestion": "人工复核该文件是否存在下载执行、外传或混淆行为",
                "engine": "yara",
            })
    return findings


def run_static_analysis(extract_dir: Path) -> dict:
    start = time.perf_counter()
    findings: list[dict] = []

    for fp in iter_code_files(extract_dir):
        findings.extend(_regex_scan_file(fp, extract_dir))

    findings.extend(_run_semgrep(extract_dir))
    findings.extend(_run_yara(extract_dir))

    return {
        "engine": "static",
        "status": "ok",
        "findings": findings,
        "duration_ms": int((time.perf_counter() - start) * 1000),
        "message": f"静态分析完成，发现 {len(findings)} 项",
    }

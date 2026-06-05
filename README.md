<div align="center">

# SkillGuard

**开源 AI Skill 安全评估平台 — 多引擎扫描，一键生成专业 HTML 报告**

上传 Skill 压缩包 → ClamAV · 静态规则 · LLM 代码审计 → 风险仪表盘与可分享报告

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[核心优势](#核心优势) ·
[功能特性](#-功能特性) ·
[快速开始](#-快速开始) ·
[配置说明](#-配置说明) ·
[API](#-api-参考) ·
[扫描引擎](#-扫描引擎) ·
[参与贡献](#-参与贡献)

</div>

---

## 项目简介

**SkillGuard**（亦名 AISkillScan）面向 AI Agent / Cursor / Claude 等生态中的 **Skill 技能包**（通常为 `.zip` / `.tar` 归档），在发布或接入前进行自动化安全评估。

与仅依赖单一工具的方案不同，SkillGuard 将 **病毒扫描、静态规则与 LLM 语义审计** 串联为一条流水线，并输出类似云安全厂商风格的 **自包含 HTML 报告**（含风险分布、分维度分析与引擎明细），适合个人开发者自检、团队内审与平台侧内容审核。

### 核心优势

- **私有化部署，资产留在内网**：可将 SkillGuard 部署在团队或公司自有环境，优秀 Skill 无需上传到第三方在线扫描平台，降低核心能力、业务逻辑与提示词被窃取或滥用的风险。
- **多引擎互补**：病毒、静态与 LLM 协同，兼顾已知恶意特征与语义层风险。
- **开箱即用**：轻量技术栈，一条命令即可在本地或 Docker 中跑通 MVP。

> **免责声明**：本工具输出仅供参考，不构成法律意见或安全担保。LLM 审计可能存在误报/漏报，高危结论请务必人工复核。

---

## 功能特性

| 能力 | 说明 |
|------|------|
| **多格式上传** | `.zip`、`.tar`、`.tar.gz`、`.tgz`，单包最大 200MB（可配置） |
| **ClamAV 病毒扫描** | 对接 ClamAV REST API；开发模式支持 Mock |
| **静态分析** | 66+ 条正则规则 + Semgrep + YARA，覆盖密钥泄露、提示注入、命令执行、供应链与混淆等 |
| **LLM 代码审计** | OpenAI 兼容 API；分片审计代码；调用异常与审计发现分离展示 |
| **HTML 安全报告** | 风险评分、8 维行为分析、Chart.js 图表、检测日志与 LLM 原始返回附录 |
| **扫描历史** | MySQL 持久化，支持进度轮询 |
| **分享链接** | 带有效期的只读分享（默认 72 小时） |
| **轻量部署** | Flask 单体 + 可选 Docker Compose，无 Redis/Celery 依赖 |
| **私有化部署** | 自托管扫描与报告，避免将内部优质 Skill 提交至外部 SaaS，保护知识产权与业务机密 |

---

## 架构概览

```mermaid
flowchart TB
    subgraph Client
        UI[Web UI]
        API[REST API]
    end

    subgraph SkillGuard
        Upload[上传与解压]
        ClamAV[ClamAV 引擎]
        Static[静态引擎<br/>Regex / Semgrep / YARA]
        LLM[LLM 审计引擎]
        Report[HTML 报告生成]
        DB[(MySQL)]
    end

    UI --> API
    API --> Upload
    Upload --> ClamAV
    Upload --> Static
    Upload --> LLM
    ClamAV --> Report
    Static --> Report
    LLM --> Report
    Report --> DB
    API --> DB
```

**扫描流水线**（后台线程异步执行）：

1. 接收归档 → 计算 SHA256 → 解压至临时目录  
2. ClamAV API 扫描原始包  
3. 静态分析（逐文件正则 + Semgrep 目录扫描 + YARA 特征匹配）  
4. LLM 对代码文件分片审计（可配置模型与 Mock）  
5. 聚合风险评分 → 生成 HTML 报告 → 清理临时文件  

---

## 快速开始

### 环境要求

- **Python** 3.11+
- **MySQL** 8.0+（或使用下方 Docker Compose 自带 MySQL）
- 可选：**Semgrep** CLI（静态分析）、**yara-python**（已在 `requirements.txt` 中）

### 本地运行

```bash
git clone https://github.com/<your-org>/SkillGuard.git
cd SkillGuard

python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
```

编辑 `.env`，至少配置 `DATABASE_URL`。**首次体验**可开启 Mock（无需真实 ClamAV / LLM）：

```env
DATABASE_URL=mysql+pymysql://skillguard:skillguard@127.0.0.1:3306/skillguard?charset=utf8mb4
LLM_MOCK=true
CLAMAV_MOCK=true
```

初始化数据库并启动：

```bash
python scripts/init_db.py
python run.py
```

浏览器访问：**http://localhost:5000**

### 生成测试样本

```bash
python scripts/create_sample_skill.py
# 将生成的 samples/demo-skill.zip 在 Web 页面上传扫描
```

### Docker Compose

```bash
docker compose up --build
```

默认在 `http://localhost:5000` 提供服务，数据库与 Mock 模式见 `docker-compose.yml`。生产环境请通过环境变量注入真实 `SECRET_KEY`、数据库与 LLM 配置。

---

## 配置说明

复制 `.env.example` 为 `.env`。常用变量如下：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DATABASE_URL` | — | **必填**。MySQL 连接串（PyMySQL） |
| `SECRET_KEY` | — | Flask 会话密钥，**生产环境务必修改** |
| `TEMP_DIR` | `./data/temp` | 解压临时目录 |
| `REPORT_DIR` | `./data/reports` | HTML 报告输出目录 |
| `UPLOAD_MAX_MB` | `200` | 上传大小上限 |
| `TEMP_CLEANUP_MINUTES` | `30` | 扫描后临时文件保留时间 |
| `CLAMAV_API_URL` | — | ClamAV REST 扫描端点 |
| `CLAMAV_API_TOKEN` | — | ClamAV API 认证 Token |
| `CLAMAV_ENABLED` | `true` | 是否启用 ClamAV |
| `CLAMAV_MOCK` | `false` | `true` 时模拟通过（开发用） |
| `LLM_API_KEY` | — | LLM API Key |
| `LLM_BASE_URL` | OpenAI 兼容地址 | 支持 Ollama、OneAPI 等 |
| `LLM_MODEL` | `gpt-4o-mini` | 模型名称 |
| `LLM_ENABLED` | `true` | 是否启用 LLM 审计 |
| `LLM_MOCK` | `false` | `true` 时本地启发式模拟 |
| `LLM_TIMEOUT` | `120` | 单次请求超时（秒） |
| `LLM_CHUNK_SIZE` | `8000` | 代码分片大小 |
| `SEMGREP_ENABLED` | `true` | 是否运行 Semgrep |
| `SEMGREP_MOCK` | `false` | `true` 时跳过 Semgrep |
| `YARA_ENABLED` | `true` | 是否运行 YARA |
| `SHARE_LINK_EXPIRE_HOURS` | `72` | 分享链接有效期 |

**LLM 接入示例（Ollama）**：

```env
LLM_MOCK=false
LLM_API_KEY=ollama
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=qwen2.5:7b
```

> ⚠️ 切勿将含真实 Key 的 `.env` 提交至 Git。`.env` 已在 `.gitignore` 中排除。

---

## API 参考

基础路径：`/api`

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/health` | 健康检查 |
| `POST` | `/scans` | 上传归档并启动扫描（`multipart/form-data`，字段 `file`），返回 `202` |
| `GET` | `/scans` | 扫描历史（`?page=1&per_page=20`） |
| `GET` | `/scans/:id` | 扫描详情（含 findings） |
| `GET` | `/scans/:id/progress` | 进度轮询 |
| `GET` | `/scans/:id/report` | HTML 报告（`?download=1` 触发下载） |
| `POST` | `/scans/:id/share` | 生成分享链接 |
| `GET` | `/share/:token` | 通过 Token 只读访问扫描结果 |

**上传示例**：

```bash
curl -X POST http://localhost:5000/api/scans \
  -F "file=@samples/demo-skill.zip"
```

**轮询进度**：

```bash
curl http://localhost:5000/api/scans/1/progress
```

---

## 扫描引擎

### 1. ClamAV（病毒引擎）

对上传的原始归档调用配置的 REST API，在解压前拦截已知恶意样本。

### 2. 静态引擎（`app/services/static_scan.py`）

| 子引擎 | 作用 |
|--------|------|
| **Regex** | 66+ 条内置规则：硬编码密钥、提示注入、命令执行、网络外传、敏感路径、供应链与混淆等 |
| **Semgrep** | Python `os.system` / `subprocess` / `pickle` / `eval` 等；Node `child_process` |
| **YARA** | 6 条启发式规则：管道进 shell、PowerShell 滥用、Webhook 外传、远程脚本等 |

扫描文件类型包括：`.py` `.js` `.ts` `.sh` `.md` `.json` `.yaml` `.env` 等（见 `iter_code_files`）。

扩展规则：直接编辑 `REGEX_RULES`、`SEMGREP_RULES_YAML`、`YARA_RULES_SOURCE`。

### 3. LLM 审计引擎（`app/services/llm_audit.py`）

- 针对代码文件分片，检测提示注入、数据外泄、权限滥用、危险 IO 等  
- 要求模型返回 **JSON 数组**；无法解析或 API 报错时记入 `errors`，**不计入**安全风险项  
- 完整原始返回与异常信息展示在报告附录  

---

## 项目结构

```
SkillGuard/
├── app/
│   ├── api/              # REST 路由
│   ├── models/           # SQLAlchemy 模型
│   ├── services/         # 扫描引擎、报告生成
│   │   ├── scanner.py    # 流水线编排
│   │   ├── static_scan.py
│   │   ├── llm_audit.py
│   │   ├── clamav.py
│   │   └── report.py
│   ├── templates/        # HTML 报告 Jinja2 模板
│   └── static/           # Web 前端页面
├── migrations/           # Alembic 数据库迁移
├── scripts/
│   ├── init_db.py
│   └── create_sample_skill.py
├── data/                 # 运行时报告与临时文件（建议 gitignore）
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── run.py
└── wsgi.py
```

---

## 生产部署建议

- 使用 **gunicorn** 或 **uvicorn** + Nginx 反向代理，关闭 `FLASK_ENV=development`
- 配置真实 **ClamAV**（HTTPS + Token）与 **LLM** API
- MySQL 启用访问控制与 SSL；定期备份
- 将 `SECRET_KEY`、API Key 仅通过环境变量或密钥管理服务注入
- 限制上传大小与并发，监控 `TEMP_DIR` / `REPORT_DIR` 磁盘占用
- 对外分享链接建议叠加鉴权或缩短 `SHARE_LINK_EXPIRE_HOURS`

---

## 路线图

当前为 **MVP v1.0**，后续计划方向（欢迎 Issue/PR）：

- [ ] 批量扫描与 CI/GitHub Action 集成
- [ ] 可插拔规则集（YAML 外置配置）
- [ ] 报告导出 PDF / SARIF
- [ ] 用户与多租户
- [ ] 动态沙箱 / 行为分析（长期）

---

## 参与贡献

我们欢迎各种贡献：

1. **Fork** 本仓库并创建特性分支  
2. 提交前请确保不携带 `.env`、真实 API Key 或 `data/` 下的私有样本  
3. 新增静态规则请附带说明与误报评估  
4. 提交 **Pull Request** 并描述变更动机与测试方式  

报告 Bug 或功能建议请使用 [GitHub Issues](https://github.com/<your-org>/SkillGuard/issues)。

开源前建议补充：

- [ ] 选择并添加 `LICENSE`（推荐 MIT 或 Apache-2.0）  
- [ ] 填写 `SECURITY.md` 漏洞披露流程  
- [ ] 将 README 中的 `<your-org>` 替换为实际仓库地址  

---

## 相关文档

- [需求清单.md](./需求清单.md) — 产品需求与 MVP 范围  
- [报告页面.md](./报告页面.md) — HTML 报告结构说明  

---

## 致谢

本项目在设计上参考了以下开源生态的最佳实践：

- [Semgrep](https://github.com/semgrep/semgrep) — 静态分析规则引擎  
- [YARA](https://github.com/VirusTotal/yara) — 恶意特征匹配  
- [Flask](https://github.com/pallets/flask) — Web 框架  

---

## 许可证

本项目采用 [MIT License](./LICENSE) 开源（请在发布前添加 `LICENSE` 文件）。

若 `LICENSE` 尚未添加，默认保留所有权利；贡献前请与维护者确认许可协议。

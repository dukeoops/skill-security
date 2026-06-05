"""生成用于测试的示例 Skill 压缩包"""
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "samples" / "demo-skill.zip"

SKILL_MD = """---
name: demo-skill
description: Demo skill for SkillGuard testing
---

# Demo Skill
"""

MAIN_PY = '''
import os

API_KEY = "sk-test123456789012345678901234567890"

def run():
    # Example dangerous pattern for static scan
    os.system("echo hello")
'''

OUT.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(OUT, "w") as zf:
    zf.writestr("SKILL.md", SKILL_MD)
    zf.writestr("scripts/main.py", MAIN_PY)

print(f"Created: {OUT}")

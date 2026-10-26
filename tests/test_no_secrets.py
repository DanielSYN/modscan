"""Guards against committing API keys. GitHub's secret scanning is the second line of defence."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "build", "dist"}
# Built from parts so this file doesn't match itself.
KEY_PATTERNS = [re.compile(p) for p in ("sk-" + r"ant-(?:api|admin)\d\d-[A-Za-z0-9_\-]{20,}",
                                        r"\bA" + r"KIA[0-9A-Z]{16}\b",
                                        r"\bgh" + r"[pousr]_[A-Za-z0-9]{36,}\b")]


def project_files():
    for path in ROOT.rglob("*"):
        if path.is_file() and not SKIP_DIRS & set(path.relative_to(ROOT).parts) and path.name != ".env":
            yield path


def test_no_api_keys_in_the_project():
    leaks = []
    for path in project_files():
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        leaks += [f"{path.relative_to(ROOT)}: {m.group()[:12]}…" for p in KEY_PATTERNS for m in p.finditer(text)]
    assert leaks == [], f"Possible secrets committed: {leaks}"


def test_env_files_are_git_ignored():
    ignored = (ROOT / ".gitignore").read_text().split()
    assert ".env" in ignored

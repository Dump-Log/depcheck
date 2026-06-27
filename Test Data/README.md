# DepCheck Test Files

This directory contains example dependency files for testing DepCheck across all supported input formats. Each file contains the same set of packages — a mix of legitimate and suspicious dependencies — so results should be consistent regardless of format.

---

## Packages Included

| Package | Version | Expected Finding |
|---------|---------|-----------------|
| `requests` | 2.28.0 | Vulnerabilities (known CVEs) |
| `flask` | 2.0.0 | Vulnerabilities (known CVEs) |
| `numpy` | 1.24.0 | Clean |
| `panadas` | 0.2 | 🔴 HIGH typosquatting — resembles `pandas` (edit distance 1) |
| `scikit-learns` | 0.1.0 | 🟡 MEDIUM typosquatting — resembles `scikit-learn` (edit distance 1) |
| `panda` | 0.3.1 | 🟡 MEDIUM typosquatting — resembles `pandas` (edit distance 1) |
| `nump` | 7.29.0 | 🔴 HIGH typosquatting — does not exist on PyPI, resembles `numpy` |

**Expected output:** 7 direct dependencies, multiple vulnerability findings on `requests` and `flask`, and 4 typosquatting findings.

---

## Supported Formats

### `requirements.txt`
Standard pip requirements format. The most common Python dependency file.

- Version specifiers are parsed directly (`==`, `>=`, `<=`, `~=`, `!=`)
- Comments (`#`) and options (`-r`, `-i`) are ignored
- All listed packages are treated as direct dependencies

---

### `pyproject.toml`
Modern Python project configuration file supporting two dependency formats:

**PEP 621** (`[project] dependencies`) — the standard format, takes priority.

**Poetry** (`[tool.poetry.dependencies]`) — only packages not already listed in PEP 621 are added, preventing duplicates. Poetry version specifiers (`^`, `~`) are converted to `>=` for pip compatibility.

> **Note:** If a package appears in both `[project]` and `[tool.poetry.dependencies]`, the PEP 621 version is used. This avoids version conflicts when a project uses both formats.

---

### `Pipfile`
Pipenv's dependency format. Uses TOML syntax with separate sections for production and development dependencies.

**Included:** `[packages]` — production dependencies only.

**Excluded:** `[dev-packages]` — development tools such as `pytest`, `black`, `mypy` etc. are intentionally skipped.

> **Trade-off:** Excluding dev packages reduces noise and focuses the scan on production attack surface, which is where supply chain risk matters most. A typosquatted `pytest` is a lower risk than a typosquatted `requests` since dev dependencies don't ship to end users. This matches the behaviour of most supply chain security tools. If you want dev packages scanned, they can be added back by including the `dev-packages` section in the parser.

---

### `setup.py`
Legacy Python packaging format. DepCheck extracts packages from the `install_requires` list using AST parsing — the file is never executed.

- Only `install_requires` is parsed (not `extras_require`, `tests_require`, or `setup_requires`)
- AST parsing is safe — no code is executed during analysis

> **Trade-off:** `extras_require` and `tests_require` are excluded for the same reason as Pipfile dev-packages — they represent optional or development-time dependencies rather than core production requirements. Future work could add an option to include extras.

---

## Notes

- `Pipfile` has no file extension. When uploading via the web UI, the file type filter is disabled so it can be accepted. The file type is detected by filename rather than extension.
- `pyproject.toml` files that use only Poetry (no PEP 621 `[project]` section) are also supported.
- All formats pass packages to pip-audit for vulnerability scanning. pip-audit requires packages to be resolvable — if a package doesn't exist on PyPI (like `nump==7.29.0`), it will appear as `not found` in the dependency list but will still be checked for typosquatting.

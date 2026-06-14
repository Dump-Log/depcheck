# DepCheck

A Web based supply chain risk scanner for Python projects. Detects typosquatted dependencies and audits for known vulnerabilities across the full transitive dependency tree.

## What it does

- Resolves the full transitive dependency tree from a `requirements.txt`
- Checks every dependency (direct and transitive) for known CVEs via pip-audit
- Detects potential typosquatting by comparing dependencies against the top 10,000 most downloaded PyPI packages
- Accepts GitHub repo URLs or uploaded `requirements.txt` files as input

## Quickstart

### Option 1 — Docker Hub (no setup required)

Requires [Docker](https://docs.docker.com/get-docker/) installed.

```bash
docker run -p 8080:8080 dumplog/depcheck
```

Then open http://localhost:8080

---

### Option 2 — Build locally from source

Requires Docker and Git installed.

```bash
git clone https://github.com/Dump-Log/depcheck.git
cd depcheck
docker build -t depcheck .
docker run -p 8080:8080 depcheck
```

Then open http://localhost:8080

---

### Test Data
the Test Data directory contains a requirements.txt which can be used for testing.

---
## Scoring

Typosquat findings are scored 0.0–1.0 based on:

| Signal | Weight |
|--------|--------|
| Package does not exist on PyPI | +0.90 |
| Edit distance 1 from popular package | +0.30 |
| Recently published (<90 days) | +0.25 |
| No source repository listed | +0.20 |
| Edit distance 2 from popular package | +0.15 |
| Missing or very short description | +0.15 |
| Only one release ever | +0.10 |
| Very early version number | +0.10 |
| Free webmail author address | +0.10 |

| Score | Risk |
|-------|------|
| ≥0.60 | High |
| ≥0.35 | Medium |
| <0.35 | Low |

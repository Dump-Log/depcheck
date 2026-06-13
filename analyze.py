"""
analyze.py — core logic for depcheck
  1. Fetch requirements.txt (local or GitHub URL)
  2. Run pip-audit to get transitive deps + vuln findings
  3. Download top 10,000 PyPI packages by download count (ground truth)
  4. For each dep, check if it resembles a popular legitimate package
     — if it does AND it has suspicious metadata, flag it as a likely typosquat
  5. Return structured results
"""

import json
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from threading import Lock
from typing import Optional

import requests
from rapidfuzz.distance import Levenshtein

# Helper structures

# pip-audit
@dataclass
class VulnFinding:
    vuln_id: str
    aliases: list[str]
    fix_versions: list[str]
    description: str

# pip-audit
@dataclass
class Dependency:
    name: str
    version: str
    is_direct: bool
    vulns: list[VulnFinding] = field(default_factory=list)

# typo squating
@dataclass
class SquatFinding:
    dep_name: str              # the package in your requirements
    dep_version: str
    resembles: str             # the popular legitimate package it looks like
    edit_distance: int
    suspicion_score: float     # 0.0 – 1.0, higher = more suspicious
    signals: list[str]
    # Enriched metadata
    pypi_url: Optional[str] = None
    first_upload_date: Optional[str] = None   # earliest release date
    latest_upload_date: Optional[str] = None  # most recent release date
    days_since_first_upload: Optional[int] = None
    days_since_latest_upload: Optional[int] = None
    total_releases: Optional[int] = None
    download_count: Optional[int] = None      # last 30 days if available
    author: Optional[str] = None
    author_email: Optional[str] = None
    source_url: Optional[str] = None
    has_wheel: Optional[bool] = None          # True if wheel published (more effort)
    has_sdist: Optional[bool] = None          # True if source dist published
    license: Optional[str] = None
    summary: Optional[str] = None

# general use
@dataclass
class AnalysisResult:
    dependencies: list[Dependency]
    squat_findings: list[SquatFinding]
    errors: list[str]

# Primary and fallback URLs for top PyPI packages list
TOP_PACKAGES_URLS = [
    "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages-30-days.min.json",
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
]

_top_packages_cache: set[str] = set()
# how many of the TOP packages to check against
TOP_TO_CHECK = 10000

# mininum score to be reported
SCORE_THRESHOLD = 0.15

# normalize to lowercase and fix -
def normalize(name: str) -> str:
    """PyPI normalisation: lowercase, collapse runs of [-_.] to '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()

# gets requirements file
# Returns tuple (requirements_text, source_label).
# Accepts a local file path, GitHub repo URL, or GitHub blob URL.
def fetch_requirements(source: str) -> tuple[str, str]:

    # if url is to main page and not raw
    if "github.com" in source and "/blob/" in source:
        # replace to standardize url
        raw_url = (source
                   .replace("github.com", "raw.githubusercontent.com")
                   .replace("/blob/", "/"))
        resp = requests.get(raw_url, timeout=10)
        resp.raise_for_status()
        return resp.text, raw_url

    # if page is to the raw
    if "githubusercontent" in source:
        resp = requests.get(source, timeout=10)
        resp.raise_for_status()
        return resp.text, source

    # no url so moving to file upload
    p = Path(source)
    if p.exists():
        return p.read_text(), str(p.resolve())

    raise ValueError(f"Cannot interpret source: {source!r}")

# Return {normalised_name: original_line} for each non-comment requirement
def _parse_req_lines(requirements_text: str) -> dict[str, str]:
    result = {}
    for line in requirements_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        name = normalize(
            line.split("==")[0].split(">=")[0].split("<=")[0]
            .split("~=")[0].split("!=")[0].split("[")[0].strip()
        )
        result[name] = line
    return result


# Returns only the dependencies not the versions if they are lsited
def _parse_direct_names(requirements_text: str) -> set[str]:
    return set(_parse_req_lines(requirements_text).keys())

# runs pip-audit on the requirements file
# returns json or nothing on fail
def _run_pip_audit_on_file(tmp_path: str) -> Optional[dict]:
    result = subprocess.run(
        ["pip-audit", "-r", tmp_path, "--format", "json"],
        capture_output=True, text=True, timeout=300,
    )
    raw = result.stdout.strip()
    if raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    return None

# wrapper for pip-audit, if full run fails due to unknown package
# re-runw ith unkonwn package removed
def run_pip_audit(requirements_text: str) -> tuple[list[Dependency], list[str]]:
    errors = []
    deps = []
    req_lines = _parse_req_lines(requirements_text)
    direct_names = set(req_lines.keys())

    # if pip-audit has unresolved packages it errors out and doens't kepe running,
    # needed logic to manage that behavior
    resolvable: dict[str, str] = dict(req_lines)   # name -> original line
    # unresolvable: set[str] = set()

    try:
        # First attempt: full requirements file
        # write file out to temp for cli processing
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(requirements_text)
            tmp_path = f.name

        # pip-audit runs
        data = _run_pip_audit_on_file(tmp_path)
        Path(tmp_path).unlink(missing_ok=True)

        # If full run failed, bisect to find which packages are unresolvable
        # binary search to discover which one is the culprit
        if data is None:
            remaining = list(resolvable.keys())
            while remaining:
                # Try all remaining packages together
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                    f.write("\n".join(resolvable[n] for n in remaining))
                    tmp_path = f.name
                data = _run_pip_audit_on_file(tmp_path)
                Path(tmp_path).unlink(missing_ok=True)

                if data is not None:
                    break  # this subset resolved cleanly

                # Binary search: try first half, mark second half as suspect
                if len(remaining) == 1:
                    # Single package that fails — mark unresolvable
                    # unresolvable.add(remaining[0])
                    del resolvable[remaining[0]]
                    remaining = list(resolvable.keys())
                    data = None
                else:
                    # Try first half
                    half = remaining[:len(remaining) // 2]
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                        f.write("\n".join(resolvable[n] for n in half))
                        tmp_path = f.name
                    half_data = _run_pip_audit_on_file(tmp_path)
                    Path(tmp_path).unlink(missing_ok=True)

                    if half_data is None:
                        # Problem is in first half — recurse on it
                        remaining = half
                    else:
                        # Problem is in second half — recurse on it
                        remaining = remaining[len(remaining) // 2:]

        # Parse resolved deps from pip-audit output
        if data:
            for item in data.get("dependencies", []):
                name = item["name"]
                version = item["version"]
                is_direct = normalize(name) in direct_names
                # VulnFinding is a dataclass
                vulns = [
                    VulnFinding(
                        vuln_id=v["id"],
                        aliases=v.get("aliases", []),
                        fix_versions=v.get("fix_versions", []),
                        description=v.get("description", "")[:300],
                    )
                    for v in item.get("vulns", [])
                ]
                deps.append(Dependency(name=name, version=version,
                                       is_direct=is_direct, vulns=vulns))

    except subprocess.TimeoutExpired:
        errors.append("pip-audit timed out after 300 seconds.")

    # Add unresolvable packages and any direct deps pip-audit didn't return
    resolved_names = {normalize(d.name) for d in deps}
    for name in direct_names:
        if name not in resolved_names:
            deps.append(Dependency(name=name, version="not found", is_direct=True))

    return deps, errors


# Get the top pypi packages, to be ground truth, assuming a typo squatted isnt in top
def get_top_pypi_packages(top_n: int = TOP_TO_CHECK, status_callback=None) -> set[str]:
    global _top_packages_cache

    #check if cache is filled to prevent extra calls
    if _top_packages_cache:
        return _top_packages_cache

    if status_callback:
        status_callback(f"Downloading top {top_n} PyPI packages list...")

    # try grabbing data from the two urls, they are mirros just diff repos
    for url in TOP_PACKAGES_URLS:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                _top_packages_cache = {
                    normalize(row["project"])
                    for row in data["rows"][:top_n]
                }
                if status_callback:
                    status_callback(f"Loaded {len(_top_packages_cache):,} popular packages as ground truth.")
                return _top_packages_cache
        except Exception:
            continue

    # All URLs failed return empty set
    if status_callback:
        status_callback("Could not fetch top packages list — typosquat detection unavailable.")
    return set()

# helper function gets json results from pypi for a package, returns empty if not found
def fetch_pypi_metadata(name: str) -> Optional[dict]:
    PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
    try:
        resp = requests.get(PYPI_JSON_URL.format(name=name), timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        pass
    return None

# Uses Levenshtein distance to try and detect potential typos, or typosquating
# distance of 2 currently, meaning 1, or 2 changes will flag, any more and it's likely a different package
# Returns (matched_name, edit_distance)
# Returns None if nothing found, or Top Package
def closest_popular_match(dep_name: str, top_packages: set[str], max_dist: int = 2) -> Optional[tuple[str, int]]:
    norm = normalize(dep_name)

    # If this package IS a top package, it's not a typosquat
    if norm in top_packages:
        return None

    best_name = None
    best_dist = max_dist + 1

    for popular in top_packages:
        dist = Levenshtein.distance(norm, popular)
        if dist <= max_dist and dist < best_dist:
            best_dist = dist
            best_name = popular

    return (best_name, best_dist) if best_name else None

# Higher score = more suspecious
def score_dep(dep: Dependency, resembles: str, edit_distance: int, metadata: dict) -> SquatFinding:
    signals = []
    score = 0.0
    info = metadata.get("info", {})
    releases = metadata.get("releases", {})

    # --- Enrich: collect all release file timestamps ---
    all_files = [f for files in releases.values() for f in files]
    all_dates = []
    for f in all_files:
        t = f.get("upload_time", "")[:10]
        if t:
            try:
                all_dates.append(date.fromisoformat(t))
            except ValueError:
                pass

    first_upload_date = str(min(all_dates)) if all_dates else None
    latest_upload_date = str(max(all_dates)) if all_dates else None
    days_since_first = (date.today() - min(all_dates)).days if all_dates else None
    days_since_latest = (date.today() - max(all_dates)).days if all_dates else None
    total_releases = len(releases)
    has_wheel = any(f.get("packagetype") == "bdist_wheel" for f in all_files)
    has_sdist = any(f.get("packagetype") == "sdist" for f in all_files)

    # --- Enrich: source URL ---
    home = info.get("home_page") or ""
    project_urls = info.get("project_urls") or {}
    source_url = (project_urls.get("Source")
                  or project_urls.get("Homepage")
                  or project_urls.get("Repository")
                  or home or None)

    # --- Enrich: author ---
    author = info.get("author") or None
    author_email = info.get("author_email") or None

    # --- Enrich: PyPI URL ---
    pypi_url = f"https://pypi.org/project/{dep.name}/"

    # --- Enrich: summary and license ---
    summary = info.get("summary") or ""
    license_id = info.get("license") or None

    # --- Scoring signals ---

    # Signal: edit distance
    if edit_distance == 1:
        score += 0.30
        signals.append(f"Single character difference from popular package '{resembles}'")
    elif edit_distance == 2:
        score += 0.15
        signals.append(f"Two character difference from popular package '{resembles}'")

    # Signal: recently first published (package is new overall)
    if days_since_first is not None:
        if days_since_first < 90:
            score += 0.25
            signals.append(f"Package is only {days_since_first} days old — very new")
        elif days_since_first < 365:
            score += 0.10
            signals.append(f"Package is less than a year old ({days_since_first} days)")

    # Signal: no source repository
    if not source_url:
        score += 0.20
        signals.append("No source repository listed")

    # Signal: missing or very short description
    if len(summary) < 10:
        score += 0.15
        signals.append("Missing or very short package description")

    # Signal: only one release ever (no maintenance history)
    if total_releases == 1:
        score += 0.10
        signals.append("Only one release — no update history")

    # Signal: very early version
    version = info.get("version", "0")
    if version.startswith("0.0."):
        score += 0.10
        signals.append(f"Very early version ({version})")

    # Signal: free webmail author address
    free_mail = ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com")
    if author_email and any(fm in author_email.lower() for fm in free_mail):
        score += 0.10
        signals.append(f"Free webmail author address ({author_email})")

    # Signal: no wheel published (less effort = less legitimate)
    if has_sdist and not has_wheel:
        score += 0.05
        signals.append("No wheel published — source-only distribution")

    return SquatFinding(
        dep_name=dep.name,
        dep_version=dep.version,
        resembles=resembles,
        edit_distance=edit_distance,
        suspicion_score=round(min(score, 1.0), 2),
        signals=signals if signals else ["No strong signals — low suspicion"],
        pypi_url=pypi_url,
        first_upload_date=first_upload_date,
        latest_upload_date=latest_upload_date,
        days_since_first_upload=days_since_first,
        days_since_latest_upload=days_since_latest,
        total_releases=total_releases,
        download_count=None,  # would need pypistats API — out of scope
        author=author,
        author_email=author_email,
        source_url=source_url,
        has_wheel=has_wheel,
        has_sdist=has_sdist,
        license=license_id,
        summary=summary or None,
    )


# Main function does the analysing
def analyze(source: str, status_callback=None, skip_squats: bool = False) -> AnalysisResult:

    errors = []

    def status(msg):
        if status_callback:
            status_callback(msg)

    # 1. Fetch requirements
    status("Fetching requirements.txt...")
    try:
        req_text, source_label = fetch_requirements(source)
    except (FileNotFoundError, ValueError, requests.RequestException) as e:
        return AnalysisResult(dependencies=[], squat_findings=[], errors=[str(e)])

    status(f"Loaded requirements from {source_label}")

    # 2. Parse raw package names directly from requirements text.
    #    This is used for squat detection and is independent of pip-audit.
    raw_names = _parse_direct_names(req_text)
    status(f"Parsed {len(raw_names)} package name(s) from requirements.")

    # 3. pip-audit — vulnerability scan.
    #    Runs in isolation; failures are recorded but do not abort the pipeline.
    status("Running pip-audit for vulnerability scan (this may take a minute)...")
    deps, audit_errors = run_pip_audit(req_text)
    if audit_errors:
        for e in audit_errors:
            errors.append(f"pip-audit: {e}")
        status(f"pip-audit encountered errors — vulnerability scan may be incomplete.")
    else:
        status(f"pip-audit resolved {len(deps)} dependencies "
               f"({sum(1 for d in deps if d.vulns)} with vulnerabilities).")

    # 4. Typosquat detection — runs against raw names, not pip-audit output.
    squat_findings = []

    if not skip_squats:
        top_packages = get_top_pypi_packages(status_callback=status)
        status("Checking package names against top PyPI packages...")

        # Build work items from raw names parsed from requirements.
        # We also include any additional transitive names resolved by pip-audit
        # so transitive deps are checked too.
        resolved_names = {normalize(d.name): d for d in deps}
        dep_lookup: dict[str, Dependency] = {}

        # Raw names first (direct deps, including unresolvable ones)
        for name in raw_names:
            if name in resolved_names:
                dep_lookup[name] = resolved_names[name]
            else:
                dep_lookup[name] = Dependency(name=name, version="unknown", is_direct=True)

        # Add transitive deps resolved by pip-audit
        for norm_name, dep in resolved_names.items():
            if norm_name not in dep_lookup:
                dep_lookup[norm_name] = dep

        work_items: list[tuple[Dependency, str, int]] = []
        for dep in dep_lookup.values():
            match = closest_popular_match(dep.name, top_packages)
            if match:
                resembles, dist = match
                work_items.append((dep, resembles, dist))

        status(f"Found {len(work_items)} package(s) resembling popular packages — scoring...")

        lock = Lock()

        def check_dep(item: tuple[Dependency, str, int]) -> Optional[SquatFinding]:
            dep, resembles, dist = item
            metadata = fetch_pypi_metadata(dep.name)

            if metadata is None:
                # Package doesn't exist on PyPI at all — likely a typo in the
                # requirements file. Flag it directly without metadata scoring.
                if dep.version == "not found" or dist == 1:
                    return SquatFinding(
                        dep_name=dep.name,
                        dep_version=dep.version,
                        resembles=resembles,
                        edit_distance=dist,
                        suspicion_score=0.90,
                        signals=[
                            f"Package does not exist on PyPI",
                            f"Single character difference from popular package '{resembles}'" if dist == 1
                            else f"Close match to popular package '{resembles}' (edit distance {dist})",
                            "Likely a typo in requirements.txt rather than a malicious package",
                        ],
                        pypi_url=None,
                    )
                return None

            finding = score_dep(dep, resembles, dist, metadata)
            return finding if finding.suspicion_score >= SCORE_THRESHOLD else None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_dep, item): item for item in work_items}
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    with lock:
                        squat_findings.append(result)

        squat_findings.sort(key=lambda f: f.suspicion_score, reverse=True)
        status(f"Squat detection complete — {len(squat_findings)} suspicious package(s) found.")
    else:
        status("Skipping typosquat detection.")

    return AnalysisResult(
        dependencies=deps,
        squat_findings=squat_findings,
        errors=errors,
    )

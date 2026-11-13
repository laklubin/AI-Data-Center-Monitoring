#!/usr/bin/env python3
"""Compile the YAML use-case library into usecases.json for the website.

Source of truth: usecases/NN-<domain>.yml (one file per domain) and
usecases/frameworks.yml (names of every ATT&CK / ATLAS / OWASP ID that a
use case maps to). The script validates everything, writes usecases.json and
refreshes the coverage table in README.md.

Usage:
    python3 scripts/build.py           # validate + write usecases.json + README table
    python3 scripts/build.py --check   # validate only; exit 1 if outputs are stale

Requires PyYAML (pip install pyyaml).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "usecases"
OUT = ROOT / "usecases.json"
README = ROOT / "README.md"

TITLE = "AI Data Center SIEM Use Cases"
LAYERS = [
    "Identity & Perimeter",
    "GPU & Physical Infrastructure",
    "Platform & Pipeline",
    "AI Stack",
    "Data & Operations",
]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
REQUIRED = ["id", "name", "severity", "description", "log_sources", "detection", "sample_log"]
ALLOWED = set(REQUIRED) | {"mappings"}
MAPPING_RE = re.compile(r"^(T[01]\d{3}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?|LLM\d{2}:2025|API\d{1,2}:2023)$")
TABLE_START = "<!-- COVERAGE:START -->"
TABLE_END = "<!-- COVERAGE:END -->"


def framework_of(mid: str) -> str:
    if mid.startswith("AML."):
        return "ATLAS"
    if re.match(r"^T0\d{3}", mid):
        return "ATT&CK ICS"
    if re.match(r"^T1\d{3}", mid):
        return "ATT&CK"
    if mid.startswith("LLM"):
        return "OWASP LLM"
    if mid.startswith("API"):
        return "OWASP API"
    return "Other"


def check_sample(text: str) -> str | None:
    """Every line that looks like a JSON object must parse (unless the whole log is one JSON document)."""
    s = text.strip()
    if s[:1] in "{[":
        try:
            json.loads(s)
            return None
        except ValueError:
            pass
    for n, line in enumerate(s.splitlines(), 1):
        ln = line.strip()
        if ln.startswith("{") and ln.endswith("}"):
            try:
                json.loads(ln)
            except ValueError as exc:
                return f"sample_log line {n} is not valid JSON: {exc}"
    return None


def load() -> tuple[list, list, dict, list[str]]:
    errors: list[str] = []
    fw_raw = yaml.safe_load((SRC / "frameworks.yml").read_text(encoding="utf-8")) or {}
    frameworks = {str(k): {"name": str(v), "framework": framework_of(str(k))} for k, v in fw_raw.items()}
    for k in frameworks:
        if not MAPPING_RE.match(k):
            errors.append(f"frameworks.yml: malformed ID {k!r}")

    categories, usecases, seen = [], [], {}
    used_ids: set[str] = set()
    files = sorted(SRC.glob("[0-9][0-9]-*.yml"))
    if not files:
        errors.append("no usecases/NN-*.yml files found")
    for path in files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        where = path.name
        for key in ("category", "code", "layer", "scope", "usecases"):
            if not doc.get(key):
                errors.append(f"{where}: missing '{key}'")
        if doc.get("layer") not in LAYERS:
            errors.append(f"{where}: layer {doc.get('layer')!r} not in {LAYERS}")
        code = str(doc.get("code", ""))
        cat = {
            "name": doc.get("category"),
            "code": code,
            "layer": doc.get("layer"),
            "scope": " ".join(str(doc.get("scope", "")).split()),
            "added": bool(doc.get("added", False)),
        }
        count = 0
        for i, uc in enumerate(doc.get("usecases") or [], 1):
            ref = f"{where} #{i} ({uc.get('id', '?')})"
            extra = set(uc) - ALLOWED
            if extra:
                errors.append(f"{ref}: unknown field(s) {sorted(extra)}")
            missing = [k for k in REQUIRED if not uc.get(k)]
            if missing:
                errors.append(f"{ref}: missing {missing}")
                continue
            uid = str(uc["id"])
            if not re.fullmatch(rf"{re.escape(code)}-\d{{3}}", uid):
                errors.append(f"{ref}: id must look like {code}-NNN")
            if uid in seen:
                errors.append(f"{ref}: duplicate id (also in {seen[uid]})")
            seen[uid] = where
            if uc["severity"] not in SEVERITIES:
                errors.append(f"{ref}: severity {uc['severity']!r} not in {SEVERITIES}")
            if not isinstance(uc["log_sources"], list) or not all(isinstance(s, str) and s.strip() for s in uc["log_sources"]):
                errors.append(f"{ref}: log_sources must be a list of strings")
            mappings = [str(m) for m in (uc.get("mappings") or [])]
            for m in mappings:
                if not MAPPING_RE.match(m):
                    errors.append(f"{ref}: malformed mapping {m!r}")
                elif m not in frameworks:
                    errors.append(f"{ref}: mapping {m!r} has no name in frameworks.yml")
                used_ids.add(m)
            if len(set(mappings)) != len(mappings):
                errors.append(f"{ref}: duplicate mappings")
            problem = check_sample(str(uc["sample_log"]))
            if problem:
                errors.append(f"{ref}: {problem}")
            usecases.append({
                "id": uid,
                "name": " ".join(str(uc["name"]).split()),
                "category": cat["name"],
                "code": code,
                "layer": cat["layer"],
                "severity": uc["severity"],
                "description": " ".join(str(uc["description"]).split()),
                "log_sources": [" ".join(s.split()) for s in uc["log_sources"]],
                "detection": " ".join(str(uc["detection"]).split()),
                "mappings": mappings,
                "sample_log": str(uc["sample_log"]).rstrip("\n"),
            })
            count += 1
        cat["count"] = count
        categories.append(cat)

    unused = sorted(set(frameworks) - used_ids)
    for k in unused:
        errors.append(f"frameworks.yml: {k} is not used by any use case (remove it)")
    frameworks = {k: frameworks[k] for k in sorted(frameworks) if k in used_ids}
    return categories, usecases, frameworks, errors


def coverage_table(categories: list, usecases: list) -> str:
    rows = ["| Layer | Domain | Scope | Use cases | Critical | High | Medium | Low |",
            "|---|---|---|---:|---:|---:|---:|---:|"]
    for layer in LAYERS:
        for c in (c for c in categories if c["layer"] == layer):
            sev = {s: sum(1 for u in usecases if u["category"] == c["name"] and u["severity"] == s) for s in SEVERITIES}
            name = f"{c['name']} *(added)*" if c["added"] else c["name"]
            rows.append(f"| {layer} | {name} | {c['scope']} | {c['count']} | "
                        + " | ".join(str(sev[s]) for s in SEVERITIES) + " |")
    total = {s: sum(1 for u in usecases if u["severity"] == s) for s in SEVERITIES}
    rows.append(f"| | **Total** | | **{len(usecases)}** | " + " | ".join(f"**{total[s]}**" for s in SEVERITIES) + " |")
    return "\n".join(rows)


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    categories, usecases, frameworks, errors = load()
    if errors:
        print(f"{len(errors)} problem(s):", file=sys.stderr)
        for e in errors:
            print("  - " + e, file=sys.stderr)
        return 1

    data = {
        "title": TITLE,
        "layers": [l for l in LAYERS if any(c["layer"] == l for c in categories)],
        "categories": [{k: c[k] for k in ("name", "code", "layer", "scope", "added", "count")} for c in categories],
        "frameworks": frameworks,
        "usecases": usecases,
    }
    payload = json.dumps(data, ensure_ascii=False, indent=1) + "\n"

    readme_new = None
    if README.exists():
        text = README.read_text(encoding="utf-8")
        if TABLE_START in text and TABLE_END in text:
            head, rest = text.split(TABLE_START, 1)
            _, tail = rest.split(TABLE_END, 1)
            readme_new = f"{head}{TABLE_START}\n{coverage_table(categories, usecases)}\n{TABLE_END}{tail}"

    stale = []
    if not OUT.exists() or OUT.read_text(encoding="utf-8") != payload:
        stale.append(OUT.name)
    if readme_new is not None and README.read_text(encoding="utf-8") != readme_new:
        stale.append(README.name)

    summary = (f"{len(usecases)} use cases · {len(categories)} domains · "
               f"{len(frameworks)} mapped techniques")
    if check_only:
        if stale:
            print(f"Out of date: {', '.join(stale)}. Run: python3 scripts/build.py", file=sys.stderr)
            return 1
        print(f"OK — {summary}")
        return 0

    OUT.write_text(payload, encoding="utf-8")
    if readme_new is not None:
        README.write_text(readme_new, encoding="utf-8")
    print(f"Wrote {OUT.name} — {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

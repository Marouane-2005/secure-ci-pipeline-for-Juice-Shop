#!/usr/bin/env python3
"""
Quality Gate - agrège les résultats de Semgrep, OWASP Dependency-Check,
Trivy et OWASP ZAP, applique les exceptions documentées, puis décide si
le build passe ou échoue selon les seuils définis.

Usage:
    python3 quality_gate.py --results-dir scan-results \
        --exceptions security-exceptions.json
"""

import argparse
import json
import sys
from datetime import date
from pathlib import Path

THRESHOLDS = {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 10, "LOW": 999}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ---------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------
def find_file(results_dir: Path, filename: str):
    matches = list(results_dir.rglob(filename))
    return matches[0] if matches else None


def safe_json_load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Impossible de lire {path}: {exc}")
        return None


def cvss_to_severity(score) -> str:
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "LOW"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def add(findings, source, severity, detail, location):
    findings.append(
        {"source": source, "severity": severity, "detail": str(detail), "location": str(location)}
    )


# ---------------------------------------------------------------------
# Parseurs (un par scanner)
# ---------------------------------------------------------------------
def parse_semgrep(results_dir, findings):
    path = find_file(results_dir, "semgrep-results.json")
    if not path:
        print("[SAST] Aucun résultat Semgrep trouvé, étape ignorée.")
        return
    data = safe_json_load(path) or {}
    severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    for r in data.get("results", []):
        raw = r.get("extra", {}).get("severity", "INFO").upper()
        add(findings, "SAST (Semgrep)", severity_map.get(raw, "LOW"),
            r.get("check_id", "unknown-rule"), r.get("path", "?"))


def parse_dependency_check(results_dir, findings):
    path = find_file(results_dir, "dependency-check-report.json")
    if not path:
        print("[SCA] Aucun résultat Dependency-Check trouvé, étape ignorée.")
        return
    data = safe_json_load(path) or {}
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities", []) or []:
            cvss = v.get("cvssv3", {}).get("baseScore")
            if cvss is None:
                cvss = v.get("cvssv2", {}).get("score", 0)
            add(findings, "SCA (Dependency-Check)", cvss_to_severity(cvss),
                v.get("name", "unknown-cve"), dep.get("fileName", "?"))


def parse_trivy(results_dir, findings):
    path = find_file(results_dir, "trivy-results.json")
    if not path:
        print("[Container] Aucun résultat Trivy trouvé, étape ignorée.")
        return
    data = safe_json_load(path) or {}
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "LOW").upper()
            if sev not in SEVERITY_ORDER:
                sev = "LOW"
            add(findings, "Container (Trivy)", sev,
                v.get("VulnerabilityID", "unknown-cve"), v.get("PkgName", "?"))


def parse_zap(results_dir, findings):
    path = find_file(results_dir, "zap-report.json")
    if not path:
        print("[DAST] Aucun résultat ZAP trouvé, étape ignorée.")
        return
    data = safe_json_load(path) or {}
    # riskcode ZAP : 3=High, 2=Medium, 1=Low, 0=Informational (ignoré)
    mapping = {3: "HIGH", 2: "MEDIUM", 1: "LOW"}
    counted = ignored = 0
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            try:
                sev = mapping.get(int(alert.get("riskcode")))
            except (TypeError, ValueError):
                sev = None
            if sev is None:
                ignored += 1
                continue
            counted += 1
            instances = alert.get("instances", [])
            location = instances[0].get("uri", site.get("@name", "?")) if instances else site.get("@name", "?")
            add(findings, "DAST (OWASP ZAP)", sev,
                f"{alert.get('alert', 'unknown-alert')} [{alert.get('pluginid', '?')}]", location)
    print(f"[DAST] {counted} alertes comptabilisées, {ignored} informationnelles ignorées.")


# ---------------------------------------------------------------------
# Exceptions documentées
# ---------------------------------------------------------------------
def load_exceptions(path):
    """Retourne la liste des exceptions valides et actives."""
    if not path or not Path(path).exists():
        print("[EXCEPTIONS] Aucun fichier d'exceptions, aucune exception appliquée.")
        return []
    data = safe_json_load(Path(path)) or {}
    active = []
    for i, exc in enumerate(data.get("exceptions", []), start=1):
        missing = [k for k in ("match", "reason", "expires") if not exc.get(k)]
        if missing:
            print(f"[EXCEPTIONS] Entrée #{i} ignorée : champs manquants {missing}.")
            continue
        try:
            expires = date.fromisoformat(exc["expires"])
        except ValueError:
            print(f"[EXCEPTIONS] Entrée #{i} ('{exc['match']}') ignorée : date invalide.")
            continue
        if expires < date.today():
            print(f"[EXCEPTIONS] Entrée '{exc['match']}' EXPIRÉE le {exc['expires']} : "
                  f"les findings correspondants redeviennent bloquants.")
            continue
        active.append(exc)
    return active


def apply_exceptions(findings, exceptions):
    """Sépare les findings en (retenus, acceptés par exception)."""
    kept, accepted = [], []
    for f in findings:
        haystack = f"{f['detail']} {f['location']}".lower()
        hit = next((e for e in exceptions if e["match"].lower() in haystack), None)
        if hit:
            accepted.append({**f, "exception": hit})
        else:
            kept.append(f)
    return kept, accepted


# ---------------------------------------------------------------------
# Évaluation et rapport
# ---------------------------------------------------------------------
def count_by_severity(findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def evaluate(counts) -> bool:
    return all(counts[s] <= THRESHOLDS[s] for s in SEVERITY_ORDER)


def md(text):
    return str(text).replace("|", "\\|")


def write_summary(counts, findings, accepted, passed, out_path: Path):
    lines = ["# 🔒 Quality Gate Report", "",
             f"**Result: {'✅ PASSED' if passed else '❌ FAILED'}**", "",
             "## Severity summary", "",
             "| Severity | Found | Threshold | Status |", "|---|---:|---:|---|"]
    for s in SEVERITY_ORDER:
        ok = "✅" if counts[s] <= THRESHOLDS[s] else "❌"
        lines.append(f"| {s} | {counts[s]} | {THRESHOLDS[s]} | {ok} |")

    per_scanner = {}
    for f in findings:
        per_scanner[f["source"]] = per_scanner.get(f["source"], 0) + 1
    if per_scanner:
        lines += ["", "## Findings by scanner", "", "| Scanner | Findings |", "|---|---:|"]
        lines += [f"| {k} | {v} |" for k, v in sorted(per_scanner.items())]

    if accepted:
        grouped = {}
        for a in accepted:
            g = grouped.setdefault(a["exception"]["match"], {"exc": a["exception"], "n": 0})
            g["n"] += 1
        lines += ["", "## Accepted risks (documented exceptions)", "",
                  "| Match | Findings excluded | Expires | Reason |", "|---|---:|---|---|"]
        for match, g in grouped.items():
            lines.append(f"| {md(match)} | {g['n']} | {g['exc']['expires']} | {md(g['exc']['reason'])} |")

    if findings:
        lines += ["", "## Top findings", "",
                  "| Source | Severity | Detail | Location |", "|---|---|---|---|"]
        ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["source"]))
        for f in ordered[:20]:
            lines.append(f"| {f['source']} | {f['severity']} | {md(f['detail'])} | {md(f['location'])} |")

    out = "\n".join(lines) + "\n"
    out_path.write_text(out, encoding="utf-8")
    print(out)


def main():
    parser = argparse.ArgumentParser(description="Centralized Security Quality Gate")
    parser.add_argument("--results-dir", required=True, type=Path)
    parser.add_argument("--exceptions", type=Path, default=None,
                        help="Fichier JSON d'exceptions documentées (optionnel)")
    args = parser.parse_args()

    if not args.results_dir.exists():
        print(f"[ERROR] Results directory not found: {args.results_dir}")
        sys.exit(1)

    all_findings = []
    parse_semgrep(args.results_dir, all_findings)
    parse_dependency_check(args.results_dir, all_findings)
    parse_trivy(args.results_dir, all_findings)
    parse_zap(args.results_dir, all_findings)

    exceptions = load_exceptions(args.exceptions)
    findings, accepted = apply_exceptions(all_findings, exceptions)
    print(f"[EXCEPTIONS] {len(accepted)} findings exclus sur {len(all_findings)}.")

    counts = count_by_severity(findings)
    passed = evaluate(counts)
    write_summary(counts, findings, accepted, passed, Path("quality_gate_summary.md"))

    if not passed:
        print("\n❌ Quality Gate FAILED - seuils de sévérité dépassés.")
        sys.exit(1)
    print("\n✅ Quality Gate PASSED.")


if __name__ == "__main__":
    main()

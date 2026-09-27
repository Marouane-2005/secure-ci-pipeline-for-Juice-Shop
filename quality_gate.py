#!/usr/bin/env python3
"""
Quality Gate — agrège les résultats de Gitleaks, Semgrep, OWASP Dependency-Check
et Trivy, puis décide si le build doit passer ou échouer selon des seuils
de sévérité définis.

Usage:
    python3 quality_gate.py --results-dir scan-results
"""

import argparse
import json
import sys
from pathlib import Path

# ----------------------------------------------------------------------
# Seuils configurables : nombre max de vulnérabilités tolérées par sévérité
# ----------------------------------------------------------------------
THRESHOLDS = {
    "CRITICAL": 0,   # Aucune vulnérabilité critique tolérée
    "HIGH": 2,       # Max 2 vulnérabilités "High" tolérées
    "MEDIUM": 10,    # Seuil plus souple pour les moyennes
    "LOW": 999,      # Pas de blocage sur les low
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def find_file(results_dir: Path, filename: str):
    """Cherche un fichier de résultat, même dans un sous-dossier d'artifact."""
    matches = list(results_dir.rglob(filename))
    return matches[0] if matches else None


def parse_semgrep(results_dir: Path, counts: dict, findings: list):
    """Parse les résultats Semgrep (SAST)."""
    f = find_file(results_dir, "semgrep-results.json")
    if not f or not f.exists():
        print("[SAST] Aucun résultat Semgrep trouvé, étape ignorée.")
        return

    data = json.loads(f.read_text())
    severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

    for result in data.get("results", []):
        raw_sev = result.get("extra", {}).get("severity", "INFO")
        sev = severity_map.get(raw_sev, "LOW")
        counts[sev] += 1
        findings.append({
            "source": "SAST (Semgrep)",
            "severity": sev,
            "detail": result.get("check_id", "unknown-rule"),
            "location": result.get("path", "?"),
        })


def parse_dependency_check(results_dir: Path, counts: dict, findings: list):
    """Parse les résultats OWASP Dependency-Check (SCA / CVE)."""
    f = find_file(results_dir, "dependency-check-report.json")
    if not f or not f.exists():
        print("[SCA] Aucun résultat Dependency-Check trouvé, étape ignorée.")
        return

    data = json.loads(f.read_text())
    for dependency in data.get("dependencies", []):
        for vuln in dependency.get("vulnerabilities", []) or []:
            cvss = vuln.get("cvssv3", {}).get("baseScore") or vuln.get("cvssv2", {}).get("score", 0)
            sev = cvss_to_severity(cvss)
            counts[sev] += 1
            findings.append({
                "source": "SCA (Dependency-Check)",
                "severity": sev,
                "detail": vuln.get("name", "unknown-cve"),
                "location": dependency.get("fileName", "?"),
            })


def parse_trivy(results_dir: Path, counts: dict, findings: list):
    """Parse les résultats Trivy (scan de conteneur)."""
    f = find_file(results_dir, "trivy-results.json")
    if not f or not f.exists():
        print("[Container] Aucun résultat Trivy trouvé, étape ignorée.")
        return

    data = json.loads(f.read_text())
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = vuln.get("Severity", "LOW").upper()
            if sev not in counts:
                sev = "LOW"
            counts[sev] += 1
            findings.append({
                "source": "Container (Trivy)",
                "severity": sev,
                "detail": vuln.get("VulnerabilityID", "unknown-cve"),
                "location": vuln.get("PkgName", "?"),
            })


def cvss_to_severity(score: float) -> str:
    """Convertit un score CVSS en catégorie de sévérité."""
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


def evaluate(counts: dict) -> bool:
    """Retourne True si le build passe, False s'il doit échouer."""
    passed = True
    for sev in SEVERITY_ORDER:
        if counts[sev] > THRESHOLDS[sev]:
            passed = False
    return passed


def write_summary(counts: dict, findings: list, passed: bool, out_path: Path):
    lines = ["# 🔒 Quality Gate Report\n"]
    lines.append(f"**Result: {'✅ PASSED' if passed else '❌ FAILED'}**\n")

    lines.append("| Severity | Found | Threshold | Status |")
    lines.append("|---|---|---|---|")
    for sev in SEVERITY_ORDER:
        status = "✅" if counts[sev] <= THRESHOLDS[sev] else "❌"
        lines.append(f"| {sev} | {counts[sev]} | {THRESHOLDS[sev]} | {status} |")

    if findings:
        lines.append("\n## Top findings\n")
        lines.append("| Source | Severity | Detail | Location |")
        lines.append("|---|---|---|---|")
        # Trie par sévérité, affiche les 20 plus importants
        sorted_findings = sorted(
            findings, key=lambda x: SEVERITY_ORDER.index(x["severity"])
        )[:20]
        for item in sorted_findings:
            lines.append(
                f"| {item['source']} | {item['severity']} | {item['detail']} | {item['location']} |"
            )

    out_path.write_text("\n".join(lines))
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True, type=Path)
    args = parser.parse_args()

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    findings = []

    parse_semgrep(args.results_dir, counts, findings)
    parse_dependency_check(args.results_dir, counts, findings)
    parse_trivy(args.results_dir, counts, findings)

    passed = evaluate(counts)
    write_summary(counts, findings, passed, Path("quality_gate_summary.md"))

    if not passed:
        print("\n❌ Quality Gate FAILED — seuils de sévérité dépassés.")
        sys.exit(1)

    print("\n✅ Quality Gate PASSED.")
    sys.exit(0)


if __name__ == "__main__":
    main()

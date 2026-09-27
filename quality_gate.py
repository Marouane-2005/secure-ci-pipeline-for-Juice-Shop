```python
#!/usr/bin/env python3
"""
Quality Gate — agrège les résultats de :

- Gitleaks (Secret Scanning)
- Semgrep (SAST)
- OWASP Dependency-Check (SCA)
- Trivy (Container Security)
- OWASP ZAP (DAST)

Puis décide si le build doit passer ou échouer selon les seuils
de sévérité définis.

Usage:
    python3 quality_gate.py --results-dir scan-results
"""

import argparse
import json
import sys
from pathlib import Path


# ----------------------------------------------------------------------
# Seuils configurables
# ----------------------------------------------------------------------
# Nombre maximum de vulnérabilités tolérées par sévérité.
THRESHOLDS = {
    "CRITICAL": 0,
    "HIGH": 2,
    "MEDIUM": 10,
    "LOW": 999,
}

SEVERITY_ORDER = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]


# ----------------------------------------------------------------------
# Utilitaires
# ----------------------------------------------------------------------
def find_file(results_dir: Path, filename: str):
    """
    Cherche un fichier de résultat dans results_dir,
    y compris dans les sous-dossiers des artifacts GitHub Actions.
    """
    matches = list(results_dir.rglob(filename))

    if not matches:
        return None

    return matches[0]


def safe_json_load(path: Path):
    """
    Charge un fichier JSON de manière sécurisée.
    Retourne None si le fichier est invalide.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[ERROR] JSON invalide dans {path}: {exc}")
        return None
    except OSError as exc:
        print(f"[ERROR] Impossible de lire {path}: {exc}")
        return None


# ----------------------------------------------------------------------
# SAST — Semgrep
# ----------------------------------------------------------------------
def parse_semgrep(results_dir: Path, counts: dict, findings: list):
    """Parse les résultats Semgrep (SAST)."""

    f = find_file(results_dir, "semgrep-results.json")

    if not f or not f.exists():
        print("[SAST] Aucun résultat Semgrep trouvé, étape ignorée.")
        return

    data = safe_json_load(f)

    if data is None:
        return

    severity_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    for result in data.get("results", []):

        raw_sev = (
            result
            .get("extra", {})
            .get("severity", "INFO")
            .upper()
        )

        sev = severity_map.get(raw_sev, "LOW")

        counts[sev] += 1

        findings.append({
            "source": "SAST (Semgrep)",
            "severity": sev,
            "detail": result.get(
                "check_id",
                "unknown-rule"
            ),
            "location": result.get(
                "path",
                "?"
            ),
        })


# ----------------------------------------------------------------------
# SCA — OWASP Dependency-Check
# ----------------------------------------------------------------------
def parse_dependency_check(
    results_dir: Path,
    counts: dict,
    findings: list,
):
    """Parse les résultats OWASP Dependency-Check (SCA / CVE)."""

    f = find_file(
        results_dir,
        "dependency-check-report.json",
    )

    if not f or not f.exists():
        print(
            "[SCA] Aucun résultat Dependency-Check trouvé, "
            "étape ignorée."
        )
        return

    data = safe_json_load(f)

    if data is None:
        return

    for dependency in data.get("dependencies", []):

        for vuln in dependency.get(
            "vulnerabilities",
            [],
        ) or []:

            cvss = (
                vuln
                .get("cvssv3", {})
                .get("baseScore")
            )

            if cvss is None:
                cvss = (
                    vuln
                    .get("cvssv2", {})
                    .get("score", 0)
                )

            sev = cvss_to_severity(cvss)

            counts[sev] += 1

            findings.append({
                "source": "SCA (Dependency-Check)",
                "severity": sev,
                "detail": vuln.get(
                    "name",
                    "unknown-cve"
                ),
                "location": dependency.get(
                    "fileName",
                    "?"
                ),
            })


# ----------------------------------------------------------------------
# Container Security — Trivy
# ----------------------------------------------------------------------
def parse_trivy(
    results_dir: Path,
    counts: dict,
    findings: list,
):
    """Parse les résultats Trivy (Container Security)."""

    f = find_file(
        results_dir,
        "trivy-results.json",
    )

    if not f or not f.exists():
        print(
            "[Container] Aucun résultat Trivy trouvé, "
            "étape ignorée."
        )
        return

    data = safe_json_load(f)

    if data is None:
        return

    for result in data.get("Results", []):

        for vuln in result.get(
            "Vulnerabilities",
            [],
        ) or []:

            sev = vuln.get(
                "Severity",
                "LOW",
            ).upper()

            if sev not in counts:
                sev = "LOW"

            counts[sev] += 1

            findings.append({
                "source": "Container (Trivy)",
                "severity": sev,
                "detail": vuln.get(
                    "VulnerabilityID",
                    "unknown-cve",
                ),
                "location": vuln.get(
                    "PkgName",
                    "?",
                ),
            })


# ----------------------------------------------------------------------
# DAST — OWASP ZAP
# ----------------------------------------------------------------------
def parse_zap(
    results_dir: Path,
    counts: dict,
    findings: list,
):
    """
    Parse les résultats OWASP ZAP (DAST).

    ZAP peut générer un rapport JSON contenant :

        site
          └── alerts
                ├── riskdesc
                ├── alert
                └── url

    Les niveaux ZAP sont convertis vers les catégories
    utilisées par le Quality Gate :

        High   -> HIGH
        Medium -> MEDIUM
        Low    -> LOW

    Les alertes Informational sont ignorées.
    """

    f = find_file(
        results_dir,
        "zap-report.json",
    )

    if not f or not f.exists():
        print(
            "[DAST] Aucun résultat OWASP ZAP trouvé, "
            "étape ignorée."
        )
        return

    data = safe_json_load(f)

    if data is None:
        return

    total_alerts = 0

    # Format standard du rapport JSON ZAP
    for site in data.get("site", []):

        for alert in site.get("alerts", []):

            total_alerts += 1

            riskdesc = (
                alert
                .get("riskdesc", "")
                .upper()
            )

            # ------------------------------------------------------
            # Conversion de la sévérité ZAP
            # ------------------------------------------------------
            if "HIGH" in riskdesc:
                sev = "HIGH"

            elif "MEDIUM" in riskdesc:
                sev = "MEDIUM"

            elif "LOW" in riskdesc:
                sev = "LOW"

            else:
                # Informational / Unknown
                continue

            counts[sev] += 1

            findings.append({
                "source": "DAST (OWASP ZAP)",
                "severity": sev,
                "detail": alert.get(
                    "alert",
                    alert.get(
                        "name",
                        "unknown-alert",
                    ),
                ),
                "location": alert.get(
                    "url",
                    site.get(
                        "@name",
                        "?",
                    ),
                ),
            })

    print(
        f"[DAST] OWASP ZAP : "
        f"{total_alerts} alerte(s) analysée(s)."
    )


# ----------------------------------------------------------------------
# CVSS -> Severity
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# Quality Gate Evaluation
# ----------------------------------------------------------------------
def evaluate(counts: dict) -> bool:
    """
    Retourne True si le build passe.

    Le build échoue dès qu'un seuil de sévérité est dépassé.
    """

    passed = True

    for sev in SEVERITY_ORDER:

        if counts[sev] > THRESHOLDS[sev]:
            passed = False

    return passed


# ----------------------------------------------------------------------
# GitHub Actions Summary
# ----------------------------------------------------------------------
def write_summary(
    counts: dict,
    findings: list,
    passed: bool,
    out_path: Path,
):
    """Génère le rapport Markdown du Quality Gate."""

    lines = [
        "# 🔒 Quality Gate Report\n"
    ]

    lines.append(
        f"**Result: "
        f"{'✅ PASSED' if passed else '❌ FAILED'}**\n"
    )

    lines.append(
        "| Severity | Found | Threshold | Status |"
    )

    lines.append(
        "|---|---:|---:|---|"
    )

    for sev in SEVERITY_ORDER:

        status = (
            "✅"
            if counts[sev] <= THRESHOLDS[sev]
            else "❌"
        )

        lines.append(
            f"| {sev} | "
            f"{counts[sev]} | "
            f"{THRESHOLDS[sev]} | "
            f"{status} |"
        )

    # --------------------------------------------------------------
    # Findings
    # --------------------------------------------------------------
    if findings:

        lines.append(
            "\n## Top findings\n"
        )

        lines.append(
            "| Source | Severity | Detail | Location |"
        )

        lines.append(
            "|---|---|---|---|"
        )

        # Les findings les plus sévères en premier
        sorted_findings = sorted(
            findings,
            key=lambda x: SEVERITY_ORDER.index(
                x["severity"]
            ),
        )[:20]

        for item in sorted_findings:

            lines.append(
                f"| {item['source']} | "
                f"{item['severity']} | "
                f"{item['detail']} | "
                f"{item['location']} |"
            )

    # --------------------------------------------------------------
    # Statistics par scanner
    # --------------------------------------------------------------
    scanner_counts = {}

    for finding in findings:

        source = finding["source"]

        scanner_counts[source] = (
            scanner_counts.get(source, 0) + 1
        )

    if scanner_counts:

        lines.append(
            "\n## Findings by scanner\n"
        )

        lines.append(
            "| Scanner | Findings |"
        )

        lines.append(
            "|---|---:|"
        )

        for source, count in sorted(
            scanner_counts.items()
        ):
            lines.append(
                f"| {source} | {count} |"
            )

    # --------------------------------------------------------------
    # Write report
    # --------------------------------------------------------------
    out_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():

    parser = argparse.ArgumentParser(
        description=(
            "Centralized Security Quality Gate"
        )
    )

    parser.add_argument(
        "--results-dir",
        required=True,
        type=Path,
        help="Directory containing scanner results",
    )

    args = parser.parse_args()

    if not args.results_dir.exists():

        print(
            f"[ERROR] Results directory not found: "
            f"{args.results_dir}"
        )

        sys.exit(1)

    # --------------------------------------------------------------
    # Initialize counters
    # --------------------------------------------------------------
    counts = {
        sev: 0
        for sev in SEVERITY_ORDER
    }

    findings = []

    # --------------------------------------------------------------
    # Parse scanner reports
    # --------------------------------------------------------------
    print("\n🔎 Parsing security scan results...\n")

    parse_semgrep(
        args.results_dir,
        counts,
        findings,
    )

    parse_dependency_check(
        args.results_dir,
        counts,
        findings,
    )

    parse_trivy(
        args.results_dir,
        counts,
        findings,
    )

    parse_zap(
        args.results_dir,
        counts,
        findings,
    )

    # --------------------------------------------------------------
    # Evaluate Quality Gate
    # --------------------------------------------------------------
    passed = evaluate(counts)

    # --------------------------------------------------------------
    # Generate summary
    # --------------------------------------------------------------
    write_summary(
        counts,
        findings,
        passed,
        Path("quality_gate_summary.md"),
    )

    # --------------------------------------------------------------
    # Exit code
    # --------------------------------------------------------------
    if not passed:

        print(
            "\n❌ Quality Gate FAILED — "
            "seuils de sévérité dépassés."
        )

        sys.exit(1)

    print(
        "\n✅ Quality Gate PASSED."
    )

    sys.exit(0)


if __name__ == "__main__":
    main()
```

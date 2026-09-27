#!/usr/bin/env python3

"""
Quality Gate — agrège les résultats de :
- Semgrep
- OWASP Dependency-Check
- Trivy
- OWASP ZAP

Puis décide si le build passe ou échoue selon les seuils définis.

Usage:
    python3 quality_gate.py --results-dir scan-results
"""

import argparse
import json
import sys
from pathlib import Path


# =========================================================
# CONFIGURATION
# =========================================================

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


# =========================================================
# UTILITAIRES
# =========================================================

def find_file(results_dir: Path, filename: str):
    """
    Recherche récursivement un fichier dans le dossier des résultats.
    """
    matches = list(results_dir.rglob(filename))

    if not matches:
        return None

    return matches[0]


def safe_json_load(path: Path):
    """
    Charge un fichier JSON sans faire planter brutalement le Quality Gate.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"[ERROR] Fichier introuvable: {path}")
        return None
    except json.JSONDecodeError as exc:
        print(f"[ERROR] JSON invalide dans {path}: {exc}")
        return None
    except OSError as exc:
        print(f"[ERROR] Impossible de lire {path}: {exc}")
        return None


# =========================================================
# SAST — SEMGREP
# =========================================================

def parse_semgrep(
    results_dir: Path,
    counts: dict,
    findings: list,
):
    """
    Analyse les résultats JSON de Semgrep.
    """

    path = find_file(
        results_dir,
        "semgrep-results.json",
    )

    if not path:
        print(
            "[SAST] Aucun résultat Semgrep trouvé, "
            "étape ignorée."
        )
        return

    data = safe_json_load(path)

    if not data:
        return

    severity_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    for result in data.get("results", []):

        raw_severity = (
            result
            .get("extra", {})
            .get("severity", "INFO")
            .upper()
        )

        severity = severity_map.get(
            raw_severity,
            "LOW",
        )

        counts[severity] += 1

        findings.append(
            {
                "source": "SAST (Semgrep)",
                "severity": severity,
                "detail": result.get(
                    "check_id",
                    "unknown-rule",
                ),
                "location": result.get(
                    "path",
                    "?",
                ),
            }
        )


# =========================================================
# SCA — OWASP DEPENDENCY-CHECK
# =========================================================

def parse_dependency_check(
    results_dir: Path,
    counts: dict,
    findings: list,
):
    """
    Analyse les résultats JSON de OWASP Dependency-Check.
    """

    path = find_file(
        results_dir,
        "dependency-check-report.json",
    )

    if not path:
        print(
            "[SCA] Aucun résultat Dependency-Check "
            "trouvé, étape ignorée."
        )
        return

    data = safe_json_load(path)

    if not data:
        return

    for dependency in data.get(
        "dependencies",
        [],
    ):

        vulnerabilities = (
            dependency.get(
                "vulnerabilities",
                [],
            )
            or []
        )

        for vulnerability in vulnerabilities:

            cvss = (
                vulnerability
                .get("cvssv3", {})
                .get("baseScore")
            )

            if cvss is None:
                cvss = (
                    vulnerability
                    .get("cvssv2", {})
                    .get("score", 0)
                )

            severity = cvss_to_severity(
                cvss
            )

            counts[severity] += 1

            findings.append(
                {
                    "source": (
                        "SCA "
                        "(Dependency-Check)"
                    ),
                    "severity": severity,
                    "detail": vulnerability.get(
                        "name",
                        "unknown-cve",
                    ),
                    "location": dependency.get(
                        "fileName",
                        "?",
                    ),
                }
            )


# =========================================================
# CONTAINER — TRIVY
# =========================================================

def parse_trivy(
    results_dir: Path,
    counts: dict,
    findings: list,
):
    """
    Analyse les résultats JSON de Trivy.
    """

    path = find_file(
        results_dir,
        "trivy-results.json",
    )

    if not path:
        print(
            "[Container] Aucun résultat Trivy "
            "trouvé, étape ignorée."
        )
        return

    data = safe_json_load(path)

    if not data:
        return

    for result in data.get(
        "Results",
        [],
    ):

        vulnerabilities = (
            result.get(
                "Vulnerabilities",
                [],
            )
            or []
        )

        for vulnerability in vulnerabilities:

            severity = (
                vulnerability
                .get("Severity", "LOW")
                .upper()
            )

            if severity not in counts:
                severity = "LOW"

            counts[severity] += 1

            findings.append(
                {
                    "source": (
                        "Container (Trivy)"
                    ),
                    "severity": severity,
                    "detail": vulnerability.get(
                        "VulnerabilityID",
                        "unknown-cve",
                    ),
                    "location": vulnerability.get(
                        "PkgName",
                        "?",
                    ),
                }
            )


# =========================================================
# DAST — OWASP ZAP
# =========================================================

def zap_risk_to_severity(riskcode):
    """
    Convertit le riskcode officiel présent dans
    le rapport JSON de ZAP.

    ZAP:
        3 = High
        2 = Medium
        1 = Low
        0 = Informational
    """

    try:
        risk = int(riskcode)
    except (
        TypeError,
        ValueError,
    ):
        return None

    mapping = {
        3: "HIGH",
        2: "MEDIUM",
        1: "LOW",
        0: None,
    }

    return mapping.get(risk)


def parse_zap(
    results_dir: Path,
    counts: dict,
    findings: list,
):
    """
    Analyse le rapport JSON généré par OWASP ZAP.

    Le rapport réel de ZAP 2.17.0 utilise :

        site[]
            alerts[]
                riskcode
                alert/name
                instances[]
    """

    path = find_file(
        results_dir,
        "zap-report.json",
    )

    if not path:
        print(
            "[DAST] Aucun résultat ZAP trouvé, "
            "étape ignorée."
        )
        return

    data = safe_json_load(path)

    if not data:
        return

    alert_count = 0
    ignored_count = 0

    for site in data.get(
        "site",
        [],
    ):

        for alert in site.get(
            "alerts",
            [],
        ):

            severity = zap_risk_to_severity(
                alert.get("riskcode")
            )

            # Les alertes informatives ZAP
            # ne sont pas comptabilisées.
            if severity is None:
                ignored_count += 1
                continue

            alert_count += 1
            counts[severity] += 1

            instances = alert.get(
                "instances",
                [],
            )

            if instances:
                first_instance = instances[0]

                location = first_instance.get(
                    "uri",
                    site.get(
                        "@name",
                        "?",
                    ),
                )
            else:
                location = site.get(
                    "@name",
                    "?",
                )

            findings.append(
                {
                    "source": (
                        "DAST "
                        "(OWASP ZAP)"
                    ),
                    "severity": severity,
                    "detail": (
                        f"{alert.get('alert', 'unknown-alert')} "
                        f"[{alert.get('pluginid', '?')}]"
                    ),
                    "location": location,
                }
            )

    print(
        f"[DAST] {alert_count} alertes "
        f"de sécurité comptabilisées."
    )

    print(
        f"[DAST] {ignored_count} alertes "
        f"informationnelles ignorées."
    )


# =========================================================
# CVSS
# =========================================================

def cvss_to_severity(score) -> str:
    """
    Convertit un score CVSS en sévérité.
    """

    try:
        score = float(score)
    except (
        TypeError,
        ValueError,
    ):
        return "LOW"

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    return "LOW"


# =========================================================
# QUALITY GATE
# =========================================================

def evaluate(counts: dict) -> bool:
    """
    Vérifie les seuils globaux.
    """

    passed = True

    for severity in SEVERITY_ORDER:

        if counts[severity] > THRESHOLDS[
            severity
        ]:
            passed = False

    return passed


# =========================================================
# SUMMARY
# =========================================================

def write_summary(
    counts: dict,
    findings: list,
    passed: bool,
    out_path: Path,
):
    """
    Génère le rapport Markdown du Quality Gate.
    """

    lines = [
        "# 🔒 Quality Gate Report",
        "",
        (
            f"**Result: "
            f"{'✅ PASSED' if passed else '❌ FAILED'}**"
        ),
        "",
        "## Severity summary",
        "",
        "| Severity | Found | Threshold | Status |",
        "|---|---:|---:|---|",
    ]

    for severity in SEVERITY_ORDER:

        status = (
            "✅"
            if counts[severity]
            <= THRESHOLDS[severity]
            else "❌"
        )

        lines.append(
            f"| {severity} | "
            f"{counts[severity]} | "
            f"{THRESHOLDS[severity]} | "
            f"{status} |"
        )

    # -----------------------------------------------------
    # Findings par scanner
    # -----------------------------------------------------

    scanner_counts = {}

    for finding in findings:

        source = finding["source"]

        scanner_counts[source] = (
            scanner_counts.get(source, 0) + 1
        )

    if scanner_counts:

        lines.extend(
            [
                "",
                "## Findings by scanner",
                "",
                "| Scanner | Findings |",
                "|---|---:|",
            ]
        )

        for source, count in sorted(
            scanner_counts.items()
        ):
            lines.append(
                f"| {source} | {count} |"
            )

    # -----------------------------------------------------
    # Top findings
    # -----------------------------------------------------

    if findings:

        lines.extend(
            [
                "",
                "## Top findings",
                "",
                "| Source | Severity | Detail | Location |",
                "|---|---|---|---|",
            ]
        )

        sorted_findings = sorted(
            findings,
            key=lambda item: (
                SEVERITY_ORDER.index(
                    item["severity"]
                ),
                item["source"],
            ),
        )

        for item in sorted_findings[:20]:

            # Nettoyage minimal pour éviter
            # de casser le tableau Markdown.
            detail = str(
                item["detail"]
            ).replace(
                "|",
                "\\|",
            )

            location = str(
                item["location"]
            ).replace(
                "|",
                "\\|",
            )

            lines.append(
                f"| {item['source']} | "
                f"{item['severity']} | "
                f"{detail} | "
                f"{location} |"
            )

    output = "\n".join(lines) + "\n"

    out_path.write_text(
        output,
        encoding="utf-8",
    )

    print(output)


# =========================================================
# MAIN
# =========================================================

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
        help=(
            "Directory containing scanner "
            "results"
        ),
    )

    args = parser.parse_args()

    if not args.results_dir.exists():
        print(
            f"[ERROR] Results directory "
            f"not found: {args.results_dir}"
        )
        sys.exit(1)

    counts = {
        severity: 0
        for severity in SEVERITY_ORDER
    }

    findings = []

    # -----------------------------------------------------
    # Parse scanner results
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # Evaluate
    # -----------------------------------------------------

    passed = evaluate(counts)

    # -----------------------------------------------------
    # Generate summary
    # -----------------------------------------------------

    write_summary(
        counts,
        findings,
        passed,
        Path(
            "quality_gate_summary.md"
        ),
    )

    # -----------------------------------------------------
    # Exit code
    # -----------------------------------------------------

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

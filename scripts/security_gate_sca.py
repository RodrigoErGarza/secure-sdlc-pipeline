
import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Control de seguridad SCA basado en CVSS."
    )
    parser.add_argument(
        "report",
        help="Ruta al reporte JSON de OWASP Dependency-Check."
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=7.0,
        help="Puntuacion CVSS minima para bloquear."
    )
    args = parser.parse_args()

    path = Path(args.report)

    if not path.is_file():
        print("ERROR: No existe el informe SCA.")
        return 2

    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"ERROR: Informe no legible o JSON invalido: {error}")
        return 2

    if not isinstance(report, dict):
        print("ERROR: Estructura del informe invalida.")
        return 2

    dependencies = report.get("dependencies")

    if not isinstance(dependencies, list):
        print("ERROR: El informe no contiene dependencias validas.")
        return 2

    exceptions = report.get("analysisExceptions", [])

    if exceptions:
        print("ERROR: El analisis SCA reporto excepciones:")
        print(json.dumps(exceptions, ensure_ascii=False, indent=2))
        print("Resultado: ANALISIS INCOMPLETO")
        return 2

    findings = []
    unscored = 0

    for dependency in dependencies:
        for vulnerability in dependency.get("vulnerabilities", []):
            scores = []

            for field in ("cvssv4", "cvssv3", "cvssv2"):
                cvss = vulnerability.get(field)
                if isinstance(cvss, dict):
                    score = cvss.get("baseScore")
                    if isinstance(score, (int, float)) and not isinstance(score, bool):
                        scores.append(float(score))

            if not scores:
                unscored += 1
                continue

            highest = max(scores)

            if highest >= args.threshold:
                findings.append({
                    "dependency": dependency.get("fileName", "Desconocida"),
                    "vulnerability": vulnerability.get("name", "Sin identificador"),
                    "score": highest
                })

    print(f"Umbral CVSS: {args.threshold}")
    print(f"Dependencias evaluadas: {len(dependencies)}")
    print(f"Hallazgos sin puntuacion: {unscored}")
    print(f"Hallazgos bloqueantes: {len(findings)}")

    for finding in findings:
        print(
            f"{finding['dependency']} | "
            f"{finding['vulnerability']} | "
            f"CVSS {finding['score']:.1f}"
        )

    if unscored:
        print(
            "ADVERTENCIA: Existen hallazgos sin puntuacion CVSS "
            "que requieren revision."
        )

    if findings:
        print("SECURITY GATE SCA: BLOQUEADO")
        return 1

    if unscored:
        print("SECURITY GATE SCA: EVALUACION INCOMPLETA")
        return 2

    print("SECURITY GATE SCA: APROBADO")
    return 0


if __name__ == "__main__":
    sys.exit(main())

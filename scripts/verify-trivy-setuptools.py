#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Gate Trivy reports, allowing only a verified pip-vendored setuptools false positive.

The exception is evaluated afresh for each image and architecture. It never
ignores other vulnerabilities or changes the image being scanned.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


# Run inside the exact candidate image, not on the Actions runner. In particular,
# search pipx's virtual environments, which are absent from system Python's path.
PROBE = r"""
import importlib.metadata
import json
from pathlib import Path

site_dirs = set()
for root in (Path('/usr/lib'), Path('/usr/local/lib'), Path('/opt/pipx')):
    if root.is_dir():
        for name in ('site-packages', 'dist-packages'):
            site_dirs.update(p for p in root.rglob(name) if p.is_dir())

installed = []
for distribution in importlib.metadata.distributions(path=sorted(map(str, site_dirs))):
    if distribution.metadata.get('Name', '').lower().replace('_', '-') == 'setuptools':
        location = Path(distribution.locate_file(''))
        installed.append({
            'version': distribution.version,
            'location': str(location),
            'package_index_present': (location / 'setuptools/package_index.py').is_file(),
        })

pip_boms = []
for site in sorted(site_dirs):
    bom = site / 'pip/_vendor/bom.cdx.json'
    if not bom.is_file():
        continue
    vendor = bom.parent
    try:
        components = json.loads(bom.read_text()).get('components', [])
        versions = sorted({str(c.get('version')) for c in components
                           if c.get('name', '').lower() == 'setuptools'})
        error = None
    except (OSError, ValueError, AttributeError) as exc:
        versions, error = [], str(exc)
    vendor_txt = vendor / 'vendor.txt'
    pins = ([line.strip() for line in vendor_txt.read_text().splitlines()
             if line.strip().startswith('setuptools==')]
            if vendor_txt.is_file() else [])
    pip_boms.append({
        'path': str(bom),
        'setuptools_versions': versions,
        'vendor_txt_pins': pins,
        'vendored_package_index_present': (vendor / 'setuptools/package_index.py').is_file(),
        'vendored_pkg_resources_present': (vendor / 'pkg_resources/__init__.py').is_file(),
        'parse_error': error,
    })

package_index_paths = sorted(str(site / 'setuptools/package_index.py')
                             for site in site_dirs
                             if (site / 'setuptools/package_index.py').is_file())
wheel_paths = sorted(str(p) for p in Path('/usr/share/python-wheels').glob('setuptools-*.whl'))
print(json.dumps({
    'installed_setuptools': sorted(installed, key=lambda d: (d['location'], d['version'])),
    'pip_boms': pip_boms,
    'package_index_paths': package_index_paths,
    'debian_setuptools_wheels': wheel_paths,
}, sort_keys=True))
"""


def read_report(report_path):
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report.get("Results"), list) or not report.get("SchemaVersion"):
        raise ValueError(f"Invalid Trivy JSON report: {report_path}")
    return report


def vulnerabilities(report):
    return [
        (result, vuln)
        for result in report.get("Results", [])
        for vuln in result.get("Vulnerabilities", []) or []
    ]


def is_pip_sbom_candidate(result, vuln):
    """Require the exact false-positive identity, not merely the CVE number."""
    if not (
        result.get("Class") == "lang-pkgs"
        and result.get("Type") == "python-pkg"
        and vuln.get("VulnerabilityID") == "CVE-2025-47273"
        and vuln.get("PkgName") == "setuptools"
        and vuln.get("InstalledVersion") == "70.3.0"
        and vuln.get("Severity") == "HIGH"
    ):
        return False
    matching = [p for p in result.get("Packages", [])
                if p.get("Name") == "setuptools" and p.get("Version") == "70.3.0"]
    return bool(matching) and all(
        p.get("AnalyzedBy") == "sbom" and not p.get("FilePath") for p in matching
    )


def is_older_than_fix(version):
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups()) < (78, 1, 1)


def assessment(evidence, reported_versions):
    versions = [is_older_than_fix(item["version"]) for item in evidence["installed_setuptools"]]
    if any(version is True for version in versions):
        return "An outdated setuptools distribution is installed: waiver denied"
    if any(version is None for version in versions):
        return "The installed setuptools version cannot be compared: manual review required"

    module_paths = set(evidence["package_index_paths"])
    owned_paths = {
        str(Path(item["location"]) / "setuptools/package_index.py")
        for item in evidence["installed_setuptools"]
    }
    if module_paths - owned_paths:
        return "Unattributed PackageIndex source detected: manual review required"

    if any(
        reported_versions.intersection(bom["setuptools_versions"])
        and not bom["vendored_package_index_present"]
        and not bom["parse_error"]
        for bom in evidence["pip_boms"]
    ):
        return "Likely false positive: version matches pip's embedded SBOM; no affected installation found"
    return "Insufficient evidence: manual review required"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image_ref", help="Immutable image reference, e.g. ghcr.io/owner/image@sha256:...")
    parser.add_argument("--profile", default="local")
    parser.add_argument("--reports-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()

    rows = []
    rejected = False
    for arch in ("amd64", "arm64"):
        report_path = args.reports_dir / f"{arch}.json"
        try:
            findings = vulnerabilities(read_report(report_path))
            candidates = [(result, vuln) for result, vuln in findings
                          if is_pip_sbom_candidate(result, vuln)]
            blocked = len(findings) - len(candidates)
            evidence = None
            waived = 0
            if candidates:
                command = [
                    "docker", "run", "--rm", "--network", "none", "--read-only",
                    "--cap-drop", "ALL",
                    "--platform", f"linux/{arch}", "--entrypoint", "/usr/bin/python3",
                    args.image_ref, "-B", "-c", PROBE,
                ]
                completed = subprocess.run(command, text=True, capture_output=True, check=True)
                evidence = json.loads(completed.stdout)
                verdict = assessment(evidence, {v["InstalledVersion"] for _, v in candidates})
                if verdict.startswith("Likely false positive:"):
                    waived = len(candidates)
                    print(f"::warning title=Temporary setuptools waiver ({arch})::{verdict}")
                else:
                    blocked += len(candidates)
            else:
                verdict = ("Target false positive absent; other vulnerabilities block publication" if blocked
                           else "Target false positive absent; temporary waiver automatically inactive")

            print(f"\n=== {args.profile} linux/{arch}: {verdict} ===")
            print("Trivy findings:", json.dumps([
                {"id": v.get("VulnerabilityID"), "package": v.get("PkgName"),
                 "version": v.get("InstalledVersion"), "severity": v.get("Severity")}
                for _, v in findings
            ], ensure_ascii=False))
            if evidence is not None:
                print("Image evidence:", json.dumps(evidence, ensure_ascii=False, indent=2))
            if blocked:
                print(f"::error title=Unwaived Trivy vulnerabilities ({arch})::{blocked} findings remain")
                rejected = True
            rows.append((arch, len(findings), waived, blocked, verdict))
        except (OSError, subprocess.CalledProcessError, ValueError, KeyError, TypeError) as exc:
            rejected = True
            detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) else str(exc)
            print(f"::error title=Image verification failed ({arch})::{detail}", file=sys.stderr)
            rows.append((arch, "?", 0, "?", f"Verification incomplete: {detail}"))

    summary = [
        f"### {args.profile}: Trivy vulnerability gate and temporary setuptools waiver",
        "",
        f"Candidate image: `{args.image_ref}`",
        "",
        "Only the verified pip-embedded SBOM false positive for `CVE-2025-47273 / setuptools 70.3.0` is eligible for a waiver. All other vulnerabilities block publication.",
        "The decision is reevaluated on every scan. The waiver becomes inactive when upstream no longer reports the false positive.",
        "",
        "| Architecture | HIGH/CRITICAL findings | Waived findings | Blocking findings | Assessment |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for arch, total, waived, blocked, verdict in rows:
        summary.append(f"| `linux/{arch}` | {total} | {waived} | {blocked} | {verdict.replace('|', '/')} |")
    summary.extend([
        "",
        "Unfiltered Trivy JSON reports are retained as Actions artifacts. In-image verification evidence is available in this step's logs.",
        "",
    ])
    content = "\n".join(summary)
    print("\n" + content)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary_file:
            summary_file.write(content)
    return 1 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())

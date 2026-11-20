#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline regression tests: the temporary waiver must never hide a real CVE."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


script = Path(__file__).resolve().parents[1] / "scripts/verify-trivy-setuptools.py"
spec = importlib.util.spec_from_file_location("trivy_gate", script)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

VULN = {
    "VulnerabilityID": "CVE-2025-47273", "PkgName": "setuptools",
    "InstalledVersion": "70.3.0", "Severity": "HIGH",
}
RESULT = {
    "Class": "lang-pkgs", "Type": "python-pkg", "Packages": [
        {"Name": "setuptools", "Version": "70.3.0", "AnalyzedBy": "sbom", "FilePath": None},
    ],
    "Vulnerabilities": [VULN],
}
EVIDENCE = {
    "installed_setuptools": [{"version": "84.2.0", "location": "/usr/lib/python3/dist-packages"}],
    "pip_boms": [{"setuptools_versions": ["70.3.0"],
                  "vendored_package_index_present": False, "parse_error": None}],
    "package_index_paths": [],
    "debian_setuptools_wheels": [],
}


class TemporaryWaiverTests(unittest.TestCase):
    def run_gate(self, reports, evidence=EVIDENCE):
        docker_response = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(evidence), stderr=""
        )
        with (
            patch.object(gate, "read_report", side_effect=reports),
            patch.object(gate.subprocess, "run", return_value=docker_response) as docker,
            patch.object(sys, "argv", ["verify", "ghcr.io/owner/image@sha256:abc"]),
            patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": "/dev/null"}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            return gate.main(), docker.call_count

    def test_exact_sbom_false_positive_can_pass(self):
        report = {"SchemaVersion": 2, "Results": [RESULT]}
        self.assertEqual(self.run_gate([report, report]), (0, 2))

    def test_another_high_cve_still_blocks(self):
        extra = {"VulnerabilityID": "CVE-9999-1234", "PkgName": "openssl",
                 "InstalledVersion": "1.0", "Severity": "HIGH"}
        report = {"SchemaVersion": 2, "Results": [{**RESULT, "Vulnerabilities": [VULN, extra]}]}
        self.assertEqual(self.run_gate([report, report])[0], 1)

    def test_real_old_setuptools_still_blocks(self):
        evidence = {**EVIDENCE, "installed_setuptools": [
            {"version": "70.3.0", "location": "/opt/venv/lib/python3.14/site-packages"}]}
        report = {"SchemaVersion": 2, "Results": [RESULT]}
        self.assertEqual(self.run_gate([report, report], evidence)[0], 1)

    def test_missing_pip_sbom_evidence_blocks(self):
        evidence = {**EVIDENCE, "pip_boms": []}
        report = {"SchemaVersion": 2, "Results": [RESULT]}
        self.assertEqual(self.run_gate([report, report], evidence)[0], 1)

    def test_non_sbom_setuptools_is_not_waived(self):
        other = {**RESULT, "Packages": [
            {"Name": "setuptools", "Version": "70.3.0", "AnalyzedBy": "python-pkg",
             "FilePath": "opt/venv/setuptools-70.3.0.dist-info/METADATA"}]}
        report = {"SchemaVersion": 2, "Results": [other]}
        self.assertEqual(self.run_gate([report, report]), (1, 0))

    def test_unrelated_version_is_not_waived(self):
        report = {"SchemaVersion": 2, "Results": [
            {**RESULT, "Vulnerabilities": [{**VULN, "InstalledVersion": "69.0.0"}]}
        ]}
        self.assertEqual(self.run_gate([report, report]), (1, 0))

    def test_upstream_fix_automatically_disables_waiver(self):
        report = {"SchemaVersion": 2, "Results": []}
        self.assertEqual(self.run_gate([report, report]), (0, 0))

    def test_malformed_report_fails_closed(self):
        with (
            patch.object(gate, "read_report", side_effect=ValueError("Invalid Trivy JSON")),
            patch.object(sys, "argv", ["verify", "ghcr.io/owner/image@sha256:abc"]),
            patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": "/dev/null"}),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(gate.main(), 1)


if __name__ == "__main__":
    unittest.main()

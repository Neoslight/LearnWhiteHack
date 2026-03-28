"""Tests du module core/reporter.py."""

from __future__ import annotations

import json

import pytest

from learnwhitehack.core.reporter import Finding, Report, Severity


def test_add_finding_basic():
    """add_finding() ajoute bien un Finding au rapport."""
    report = Report(target_url="https://example.com")
    f = report.add_finding(
        module="test.module",
        severity="HIGH",
        title="Test finding",
        detail="Détail du test",
    )
    assert f.severity == Severity.HIGH
    assert len(report.findings) == 1


def test_summary_counts():
    """summary() retourne les bons comptages par sévérité."""
    report = Report()
    report.add_finding("m", "HIGH", "h1", "")
    report.add_finding("m", "HIGH", "h2", "")
    report.add_finding("m", "LOW", "l1", "")
    s = report.summary()
    assert s["HIGH"] == 2
    assert s["LOW"] == 1
    assert s["CRITICAL"] == 0


def test_save_creates_json(tmp_path):
    """save() crée bien un fichier JSON valide."""
    report = Report(target_url="https://example.com")
    report.add_finding("mod", Severity.INFO, "Info finding", "Détail")
    json_path = report.save(str(tmp_path))
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert data["meta"]["tool"] == "learnwhitehack"
    assert len(data["findings"]) == 1


def test_save_creates_markdown(tmp_path):
    """save() crée aussi un fichier Markdown."""
    report = Report(target_url="https://example.com")
    report.add_finding("mod", Severity.MEDIUM, "Medium finding", "Détail")
    json_path = report.save(str(tmp_path))
    md_path = json_path.with_suffix(".md")
    assert md_path.exists()
    assert "# Rapport" in md_path.read_text()


def test_severity_string_coercion():
    """add_finding() accepte des strings en majuscule ou minuscule."""
    report = Report()
    f1 = report.add_finding("m", "critical", "t", "d")
    f2 = report.add_finding("m", "INFO", "t", "d")
    assert f1.severity == Severity.CRITICAL
    assert f2.severity == Severity.INFO

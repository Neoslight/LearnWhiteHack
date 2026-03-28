"""Tests du module recon/well_known.py."""

from __future__ import annotations

import responses as responses_lib

from learnwhitehack.recon import well_known
from learnwhitehack.core.reporter import Severity


@responses_lib.activate
def test_finds_security_txt(sample_config, sample_report):
    """Un security.txt accessible doit créer un finding."""
    responses_lib.add(
        responses_lib.GET,
        "https://test.example.com/.well-known/security.txt",
        body="Contact: security@example.com",
        status=200,
    )
    # Mock tout le reste en 404
    responses_lib.add(responses_lib.GET, responses_lib.PassthroughSend(), status=404)

    well_known.run(sample_config, sample_report)
    titles = [f.title for f in sample_report.findings]
    assert any(".well-known/security.txt" in t for t in titles)


@responses_lib.activate
def test_no_findings_on_404(sample_config, sample_report):
    """Aucun finding si tous les chemins retournent 404."""
    # All 404
    responses_lib.add(
        responses_lib.GET,
        responses_lib.PassthroughSend(),
        status=404,
    )
    well_known.run(sample_config, sample_report)
    # Peut avoir des findings 403 mais pas de 200
    found_200 = [f for f in sample_report.findings if "exposé" in f.title.lower()]
    assert len(found_200) == 0

"""Tests du module wordpress/fingerprint.py."""

from __future__ import annotations

import responses as responses_lib

from learnwhitehack.wordpress import fingerprint


@responses_lib.activate
def test_detects_wp_version_from_meta(sample_config, sample_report):
    """La version WP doit être extraite du meta generator."""
    html = '<meta name="generator" content="WordPress 6.4.2" />'
    responses_lib.add(responses_lib.GET, "https://test.example.com/", body=html, status=200)
    responses_lib.add(responses_lib.GET, responses_lib.PassthroughSend(), status=404)

    result = fingerprint.run(sample_config, sample_report)
    assert result.get("version") == "6.4.2"


@responses_lib.activate
def test_detects_plugins(sample_config, sample_report):
    """Les plugins doivent être extraits des chemins wp-content/plugins/."""
    html = '<link href="/wp-content/plugins/woocommerce/style.css">'
    responses_lib.add(responses_lib.GET, "https://test.example.com/", body=html, status=200)
    responses_lib.add(responses_lib.GET, responses_lib.PassthroughSend(), status=404)

    result = fingerprint.run(sample_config, sample_report)
    assert "woocommerce" in result.get("plugins", [])


@responses_lib.activate
def test_no_wp_version(sample_config, sample_report):
    """Si pas de meta generator, version=None."""
    responses_lib.add(
        responses_lib.GET, "https://test.example.com/",
        body="<html><body>Hello</body></html>",
        status=200,
    )
    responses_lib.add(responses_lib.GET, responses_lib.PassthroughSend(), status=404)

    result = fingerprint.run(sample_config, sample_report)
    assert result.get("version") is None

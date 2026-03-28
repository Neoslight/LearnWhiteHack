"""Tests du module core/http_client.py."""

from __future__ import annotations

import responses as responses_lib

from learnwhitehack.core.http_client import StealthSession, make_session


def test_make_session_returns_stealth_session():
    session = make_session(min_delay=0, max_delay=0)
    assert isinstance(session, StealthSession)


@responses_lib.activate
def test_ua_rotation():
    """Chaque requête doit avoir un User-Agent (issu du pool)."""
    responses_lib.add(responses_lib.GET, "https://example.com/", body="OK", status=200)
    responses_lib.add(responses_lib.GET, "https://example.com/", body="OK", status=200)

    session = make_session(min_delay=0, max_delay=0)
    session.get("https://example.com/")
    session.get("https://example.com/")

    # Vérifier que les requêtes ont bien un UA
    for call in responses_lib.calls:
        assert "User-Agent" in call.request.headers
        assert len(call.request.headers["User-Agent"]) > 10


@responses_lib.activate
def test_session_follows_redirects():
    """La session suit les redirections par défaut."""
    responses_lib.add(
        responses_lib.GET, "https://example.com/old",
        status=301,
        headers={"Location": "https://example.com/new"},
    )
    responses_lib.add(responses_lib.GET, "https://example.com/new", body="New page", status=200)

    session = make_session(min_delay=0, max_delay=0)
    resp = session.get("https://example.com/old")
    assert resp.status_code == 200

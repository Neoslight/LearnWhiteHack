"""Énumération et fuzzing d'endpoints GraphQL."""

from __future__ import annotations

import re
from typing import Optional

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity
from learnwhitehack.core.state import ScanContext

log = get_logger("scanner.graphql_enum")

_DEFAULT_ENDPOINTS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/gql",
    "/query",
    "/graph",
    "/api/v2/graphql",
    "/graphql/v1",
]

_INTROSPECTION_QUERY = (
    "{ __schema { queryType { name } types { name kind fields { name } } } }"
)

# Champs courants à fuzzer si l'introspection est désactivée
_COMMON_FIELDS = [
    "user", "users", "me", "admin", "config", "settings",
    "files", "uploads", "search", "login", "auth", "token",
    "products", "orders", "customers", "accounts", "roles",
    "permissions", "secrets", "emails",
]

# Regex pour détecter les suggestions "Did you mean X?"
_RE_SUGGESTION = re.compile(
    r'[Dd]id you mean ["\u201c]([^"\u201d]+)["\u201d]'
)


def _send_graphql(
    session: object, url: str, query: str, timeout: int
) -> tuple[int, dict[str, object] | None]:
    """Envoie une requête GraphQL (POST JSON). Retourne (status_http, json_ou_None)."""
    try:
        resp = session.post(  # type: ignore[attr-defined]
            url,
            json={"query": query},
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, None
    except Exception as exc:
        log.debug(f"Erreur GraphQL POST {url}: {exc}")
        return 0, None


def _parse_schema_types(data: dict[str, object]) -> list[str]:
    """Extrait les noms de types depuis une réponse d'introspection réussie."""
    try:
        types = data["data"]["__schema"]["types"]  # type: ignore[index]
        return [
            t["name"]
            for t in types  # type: ignore[union-attr]
            if isinstance(t, dict) and not str(t.get("name", "")).startswith("__")
        ]
    except (KeyError, TypeError):
        return []


def _parse_field_suggestions(data: dict[str, object]) -> list[str]:
    """Extrait les suggestions de champs depuis les messages d'erreur GraphQL."""
    suggestions: list[str] = []
    try:
        for error in data.get("errors", []):  # type: ignore[union-attr]
            msg = str(error.get("message", ""))
            suggestions.extend(_RE_SUGGESTION.findall(msg))
    except Exception:
        pass
    return suggestions


def run(
    cfg: AppConfig,
    report: Report,
    endpoints: list[str] | None = None,
    context: Optional[ScanContext] = None,
) -> list[dict[str, object]]:
    """Détecte les endpoints GraphQL et teste l'introspection / les fuites de schéma."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return []

    # Synergy directory_enum → graphql_enum : enrichir les endpoints depuis les chemins découverts
    _API_KEYWORDS = {"api", "graphql", "v1", "v2", "gql", "graph", "query"}
    ctx_endpoints: list[str] = []
    if context is not None:
        ctx_endpoints = [
            p for p in context.exposed_files
            if any(kw in p.lower() for kw in _API_KEYWORDS)
        ]

    base_endpoints = endpoints or _DEFAULT_ENDPOINTS
    test_endpoints = list(dict.fromkeys(base_endpoints + ctx_endpoints))
    if ctx_endpoints:
        log.info(f"  [cyan]Synergy dir_enum[/] : {len(ctx_endpoints)} endpoint(s) injectés depuis contexte")

    log.info(
        f"[bold]scanner.graphql_enum[/] → {base_url} "
        f"({len(test_endpoints)} endpoints)"
    )

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    results: list[dict[str, object]] = []

    for path in test_endpoints:
        url = base_url + path
        status, data = _send_graphql(session, url, _INTROSPECTION_QUERY, cfg.http.timeout)

        # Pas de réponse ou endpoint inexistant
        if status == 0 or status not in (200, 400, 403):
            continue

        log.info(f"  [yellow]Endpoint GraphQL détecté[/] : {url} (HTTP {status})")
        result: dict[str, object] = {
            "url": url,
            "http_status": status,
            "introspection": False,
            "types": [],
            "suggestions": [],
        }

        if data and isinstance(data.get("data"), dict) and data["data"]:
            # Introspection active — schéma complet exposé
            schema_types = _parse_schema_types(data)
            result["introspection"] = True
            result["types"] = schema_types
            log.info(f"    [red]Introspection ACTIVÉE[/] — {len(schema_types)} types exposés")
            report.add_finding(
                module="scanner.graphql_enum",
                severity=Severity.HIGH,
                title=f"Introspection GraphQL activée : {path}",
                detail=(
                    f"L'endpoint GraphQL {url} a l'introspection activée, "
                    "exposant le schéma complet de l'API (types, champs, mutations)."
                ),
                evidence={
                    "url": url,
                    "types_count": len(schema_types),
                    "types_sample": schema_types[:20],
                },
                references=[
                    "https://graphql.org/learn/introspection/",
                    "https://portswigger.net/web-security/graphql",
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
            )

        elif data and "errors" in data:
            errors_text = str(data.get("errors", "")).lower()

            if "introspection" in errors_text:
                # Introspection désactivée — fuzzing de suggestions
                log.info("    Introspection désactivée — fuzzing de suggestions de champs…")
                all_suggestions: list[str] = []

                for field in _COMMON_FIELDS:
                    probe_query = f"{{ {field} }}"
                    _, probe_data = _send_graphql(session, url, probe_query, cfg.http.timeout)
                    if probe_data:
                        suggestions = _parse_field_suggestions(probe_data)
                        all_suggestions.extend(suggestions)

                unique_suggestions = list(dict.fromkeys(all_suggestions))
                result["suggestions"] = unique_suggestions

                if unique_suggestions:
                    log.info(f"    [yellow]Suggestions de champs leakées[/] : {unique_suggestions}")
                    report.add_finding(
                        module="scanner.graphql_enum",
                        severity=Severity.MEDIUM,
                        title=f"Suggestions de champs GraphQL exposées : {path}",
                        detail=(
                            "L'introspection est désactivée mais les messages d'erreur "
                            "révèlent des noms de champs/requêtes via les suggestions."
                        ),
                        evidence={"url": url, "suggested_fields": unique_suggestions},
                        references=["https://portswigger.net/web-security/graphql"],
                    )
                else:
                    report.add_finding(
                        module="scanner.graphql_enum",
                        severity=Severity.LOW,
                        title=f"Endpoint GraphQL détecté (introspection désactivée) : {path}",
                        detail=(
                            "Un endpoint GraphQL a été trouvé. "
                            "L'introspection est désactivée et aucune fuite de champs n'a été détectée."
                        ),
                        evidence={"url": url, "http_status": status},
                        references=["https://portswigger.net/web-security/graphql"],
                    )
            else:
                # Endpoint GraphQL confirmé (erreur de syntaxe normale)
                report.add_finding(
                    module="scanner.graphql_enum",
                    severity=Severity.LOW,
                    title=f"Endpoint GraphQL détecté : {path}",
                    detail="Un endpoint GraphQL a été trouvé et répond aux requêtes.",
                    evidence={"url": url, "http_status": status},
                    references=["https://portswigger.net/web-security/graphql"],
                )

        results.append(result)

    if not results:
        log.info("  Aucun endpoint GraphQL trouvé.")

    return results

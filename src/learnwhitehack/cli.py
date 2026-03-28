"""Point d'entrée CLI principal — commande `lwh`."""

from __future__ import annotations

from pathlib import Path

import click

from learnwhitehack.core.config import load_config
from learnwhitehack.core.logger import setup_logging
from learnwhitehack.core.reporter import Report

# ---------------------------------------------------------------------------
# Contexte partagé
# ---------------------------------------------------------------------------

pass_cfg = click.make_pass_decorator(dict, ensure=True)


def _get_cfg(ctx: click.Context) -> dict:  # type: ignore[type-arg]
    return ctx.ensure_object(dict)


# ---------------------------------------------------------------------------
# Groupe racine
# ---------------------------------------------------------------------------

@click.group()
@click.option("--config", "config_file", type=click.Path(exists=True, path_type=Path),
              help="Fichier de configuration TOML (.toml)")
@click.option("--target", "-t", default=None, help="URL de la cible (ex: https://example.com)")
@click.option("--ip", default=None, help="IP de la cible (pour modules scanner)")
@click.option("--output-dir", "-o", default=None, help="Dossier de sortie des rapports")
@click.option("--verbose", "-v", is_flag=True, help="Mode verbose (logs DEBUG)")
@click.option("--no-color", is_flag=True, help="Désactiver les couleurs")
@click.option("--dry-run", is_flag=True, help="Simuler sans effectuer de requêtes")
@click.pass_context
def cli(ctx: click.Context, config_file: Path | None, target: str | None,
        ip: str | None, output_dir: str | None, verbose: bool,
        no_color: bool, dry_run: bool) -> None:
    """learnwhitehack — Toolkit OSINT & ethical hacking (cibles autorisées uniquement)."""
    ctx.ensure_object(dict)
    cfg = load_config(config_file, target_url=target, target_ip=ip, output_dir=output_dir)
    if ip:
        cfg.target.ip = ip
    logger = setup_logging(verbose=verbose, log_dir=cfg.output.dir)
    ctx.obj["cfg"] = cfg
    ctx.obj["logger"] = logger
    ctx.obj["dry_run"] = dry_run
    ctx.obj["report"] = Report(target_url=cfg.target.url, target_ip=cfg.target.ip)


# ---------------------------------------------------------------------------
# Groupe : recon
# ---------------------------------------------------------------------------

@cli.group()
def recon() -> None:
    """Modules de reconnaissance passive et active."""


@recon.command("well-known")
@click.pass_context
def recon_well_known(ctx: click.Context) -> None:
    """Énumère les fichiers .well-known et fichiers sensibles."""
    from learnwhitehack.recon import well_known
    obj = ctx.obj
    well_known.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@recon.command("rss-metadata")
@click.pass_context
def recon_rss(ctx: click.Context) -> None:
    """Extrait métadonnées depuis les flux RSS et readmes de plugins."""
    from learnwhitehack.recon import rss_metadata
    obj = ctx.obj
    rss_metadata.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@recon.command("author-archives")
@click.option("--max-id", default=10, show_default=True, help="ID maximum à tester")
@click.pass_context
def recon_authors(ctx: click.Context, max_id: int) -> None:
    """Énumère les auteurs WordPress via ?author=N."""
    from learnwhitehack.recon import author_archives
    obj = ctx.obj
    author_archives.run(obj["cfg"], obj["report"], max_id=max_id)
    obj["report"].save(obj["cfg"].output.dir)


@recon.command("headers")
@click.pass_context
def recon_headers(ctx: click.Context) -> None:
    """Audite les headers HTTP de sécurité."""
    from learnwhitehack.recon import headers_audit
    obj = ctx.obj
    headers_audit.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@recon.command("ssl")
@click.pass_context
def recon_ssl(ctx: click.Context) -> None:
    """Audite la configuration SSL/TLS (version, cert, cipher suites)."""
    from learnwhitehack.recon import ssl_audit
    obj = ctx.obj
    ssl_audit.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@recon.command("subdomains")
@click.option("--no-bruteforce", is_flag=True, help="Utiliser uniquement crt.sh")
@click.option("--wordlist", type=click.Path(path_type=Path), default=None)
@click.pass_context
def recon_subdomains(ctx: click.Context, no_bruteforce: bool, wordlist: Path | None) -> None:
    """Énumère les sous-domaines via crt.sh et bruteforce DNS."""
    from learnwhitehack.recon import subdomain_enum
    obj = ctx.obj
    subdomain_enum.run(obj["cfg"], obj["report"], wordlist_path=wordlist, bruteforce=not no_bruteforce)
    obj["report"].save(obj["cfg"].output.dir)


@recon.command("whois")
@click.pass_context
def recon_whois(ctx: click.Context) -> None:
    """Récupère les informations WHOIS/RDAP du domaine cible."""
    from learnwhitehack.recon import whois_lookup
    obj = ctx.obj
    whois_lookup.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@recon.command("emails")
@click.pass_context
def recon_emails(ctx: click.Context) -> None:
    """Récolte les adresses email exposées sur le site."""
    from learnwhitehack.recon import email_harvester
    obj = ctx.obj
    email_harvester.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@recon.command("js")
@click.pass_context
def recon_js(ctx: click.Context) -> None:
    """Analyse les fichiers JS (endpoints, clés, commentaires suspects)."""
    from learnwhitehack.recon import js_analyzer
    obj = ctx.obj
    js_analyzer.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@recon.command("sitemap")
@click.pass_context
def recon_sitemap(ctx: click.Context) -> None:
    """Cartographie les URLs via sitemap.xml et robots.txt."""
    from learnwhitehack.recon import sitemap_crawler
    obj = ctx.obj
    sitemap_crawler.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


# ---------------------------------------------------------------------------
# Groupe : wordpress
# ---------------------------------------------------------------------------

@cli.group()
def wordpress() -> None:
    """Modules spécifiques WordPress."""


@wordpress.command("fingerprint")
@click.pass_context
def wp_fingerprint(ctx: click.Context) -> None:
    """Détecte la version WP, les thèmes et plugins."""
    from learnwhitehack.wordpress import fingerprint
    obj = ctx.obj
    fingerprint.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@wordpress.command("api-users")
@click.pass_context
def wp_api_users(ctx: click.Context) -> None:
    """Énumère les utilisateurs via l'API REST WordPress."""
    from learnwhitehack.wordpress import api_users
    obj = ctx.obj
    api_users.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@wordpress.command("plugin-fuzz")
@click.option("--plugins", "-p", multiple=True, help="Noms de plugins à tester")
@click.option("--wordlist", type=click.Path(path_type=Path), default=None)
@click.pass_context
def wp_plugin_fuzz(ctx: click.Context, plugins: tuple[str, ...], wordlist: Path | None) -> None:
    """Fuzz les chemins de plugins pour trouver fichiers exposés."""
    from learnwhitehack.wordpress import plugin_fuzzer
    obj = ctx.obj
    plugin_fuzzer.run(obj["cfg"], obj["report"], plugins=list(plugins), wordlist_path=wordlist)
    obj["report"].save(obj["cfg"].output.dir)


@wordpress.command("xmlrpc")
@click.pass_context
def wp_xmlrpc(ctx: click.Context) -> None:
    """Détecte et teste XML-RPC WordPress."""
    from learnwhitehack.wordpress import xmlrpc_probe
    obj = ctx.obj
    xmlrpc_probe.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@wordpress.command("login-enum")
@click.option("--users", "-u", multiple=True, help="Usernames à tester")
@click.pass_context
def wp_login_enum(ctx: click.Context, users: tuple[str, ...]) -> None:
    """Confirme les usernames valides via wp-login.php."""
    from learnwhitehack.wordpress import login_enum
    obj = ctx.obj
    login_enum.run(obj["cfg"], obj["report"], usernames=list(users) or None)
    obj["report"].save(obj["cfg"].output.dir)


@wordpress.command("config-leaks")
@click.pass_context
def wp_config_leaks(ctx: click.Context) -> None:
    """Cherche les fichiers de configuration et backups exposés."""
    from learnwhitehack.wordpress import config_leaks
    obj = ctx.obj
    config_leaks.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@wordpress.command("full-recon")
@click.option("--max-author-id", default=10, show_default=True)
@click.pass_context
def wp_full_recon(ctx: click.Context, max_author_id: int) -> None:
    """Lance tous les modules WordPress en séquence et agrège les users."""
    from learnwhitehack.wordpress import (
        fingerprint, api_users, plugin_fuzzer, xmlrpc_probe,
        login_enum, config_leaks, user_bruteforce_prep,
    )
    from learnwhitehack.recon import author_archives

    obj = ctx.obj
    cfg = obj["cfg"]
    report = obj["report"]

    fp_result = fingerprint.run(cfg, report)
    users_api = api_users.run(cfg, report)
    users_archive = author_archives.run(cfg, report, max_id=max_author_id)
    config_leaks.run(cfg, report)
    xmlrpc_probe.run(cfg, report)

    # Plugins détectés → fuzz
    detected_plugins = fp_result.get("plugins", [])
    if detected_plugins:
        plugin_fuzzer.run(cfg, report, plugins=detected_plugins)

    # Préparer liste usernames
    out_file = str(Path(cfg.output.dir) / "usernames.txt")
    usernames = user_bruteforce_prep.run(
        cfg, report,
        users_from_api=users_api,
        users_from_archives=users_archive,
        output_file=out_file,
    )

    # Confirmer les valides
    if usernames:
        login_enum.run(cfg, report, usernames=usernames)

    saved = report.save(cfg.output.dir, prefix="wp_full_recon")
    click.echo(f"\nRapport sauvegardé : {saved}")
    report.print_summary()


# ---------------------------------------------------------------------------
# Groupe : scanner
# ---------------------------------------------------------------------------

@cli.group()
def scanner() -> None:
    """Modules de scan réseau."""


@scanner.command("ports")
@click.option("--range", "port_range", default=None, help="Plage de ports (ex: 1-1024)")
@click.option("--threads", default=None, type=int, help="Threads parallèles")
@click.pass_context
def scan_ports(ctx: click.Context, port_range: str | None, threads: int | None) -> None:
    """Scan TCP multi-threadé avec ordre aléatoire."""
    from learnwhitehack.scanner import port_scanner
    obj = ctx.obj
    cfg = obj["cfg"]
    if port_range:
        cfg.scan.port_range = port_range
    if threads:
        cfg.scan.threads = threads
    port_scanner.run(cfg, obj["report"])
    obj["report"].save(cfg.output.dir)


@scanner.command("banners")
@click.option("--ports", "-p", default=None, help="Ports séparés par virgule (ex: 22,80,443)")
@click.pass_context
def scan_banners(ctx: click.Context, ports: str | None) -> None:
    """Récupère les banners de services réseau."""
    from learnwhitehack.scanner import banner_grabber
    obj = ctx.obj
    port_list = [int(p) for p in ports.split(",")] if ports else None
    banner_grabber.run(obj["cfg"], obj["report"], ports=port_list)
    obj["report"].save(obj["cfg"].output.dir)


@scanner.command("dir-enum")
@click.option("--wordlist", type=click.Path(path_type=Path), default=None)
@click.option("--extensions", "-e", default=None, help="Extensions à tester (ex: php,html,txt)")
@click.option("--threads", default=20, show_default=True)
@click.pass_context
def scan_dir_enum(ctx: click.Context, wordlist: Path | None, extensions: str | None, threads: int) -> None:
    """Bruteforce de chemins HTTP."""
    from learnwhitehack.scanner import directory_enum
    obj = ctx.obj
    ext_list = extensions.split(",") if extensions else None
    directory_enum.run(obj["cfg"], obj["report"], wordlist_path=wordlist, extensions=ext_list, threads=threads)
    obj["report"].save(obj["cfg"].output.dir)


@scanner.command("tech")
@click.pass_context
def scan_tech(ctx: click.Context) -> None:
    """Détecte la stack technique (headers, cookies, patterns HTML)."""
    from learnwhitehack.scanner import tech_fingerprint
    obj = ctx.obj
    tech_fingerprint.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


# ---------------------------------------------------------------------------
# Groupe : vuln
# ---------------------------------------------------------------------------

@cli.group()
def vuln() -> None:
    """Modules de détection de vulnérabilités."""


@vuln.command("cve-search")
@click.option("--keyword", "-k", multiple=True, help="Mot-clé à rechercher (répétable)")
@click.option("--max-results", default=None, type=int)
@click.pass_context
def vuln_cve(ctx: click.Context, keyword: tuple[str, ...], max_results: int | None) -> None:
    """Recherche des CVEs dans la base NVD."""
    from learnwhitehack.vuln import cve_search
    obj = ctx.obj
    cve_search.run(obj["cfg"], obj["report"], keywords=list(keyword) or None)
    obj["report"].save(obj["cfg"].output.dir)


@vuln.command("headers")
@click.pass_context
def vuln_headers(ctx: click.Context) -> None:
    """Détecte Host Header Injection et Open Redirect."""
    from learnwhitehack.vuln import header_injection
    obj = ctx.obj
    header_injection.run(obj["cfg"], obj["report"])
    obj["report"].save(obj["cfg"].output.dir)


@vuln.command("sqli")
@click.option("--params", "-p", default=None, help="Paramètres à tester (ex: id,page,q)")
@click.pass_context
def vuln_sqli(ctx: click.Context, params: str | None) -> None:
    """Détecte les injections SQL (error-based) sur paramètres GET."""
    from learnwhitehack.vuln import sqli_probe
    obj = ctx.obj
    param_list = params.split(",") if params else None
    sqli_probe.run(obj["cfg"], obj["report"], params=param_list)
    obj["report"].save(obj["cfg"].output.dir)


@vuln.command("lfi")
@click.option("--params", "-p", default=None, help="Paramètres à tester (ex: page,file,include)")
@click.pass_context
def vuln_lfi(ctx: click.Context, params: str | None) -> None:
    """Détecte les Local File Inclusion sur paramètres suspects."""
    from learnwhitehack.vuln import lfi_probe
    obj = ctx.obj
    param_list = params.split(",") if params else None
    lfi_probe.run(obj["cfg"], obj["report"], params=param_list)
    obj["report"].save(obj["cfg"].output.dir)


# ---------------------------------------------------------------------------
# Groupe : reporting
# ---------------------------------------------------------------------------

@cli.group()
def reporting() -> None:
    """Outils de traitement des rapports."""


@reporting.command("diff")
@click.argument("before", type=click.Path(exists=True, path_type=Path))
@click.argument("after", type=click.Path(exists=True, path_type=Path))
def report_diff(before: Path, after: Path) -> None:
    """Compare deux rapports JSON et affiche les changements."""
    from learnwhitehack.reporting import diff_reports
    diff_reports.diff(before, after)


@reporting.command("html")
@click.argument("report_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def report_html(report_file: Path, output: Path | None) -> None:
    """Exporte un rapport JSON en HTML standalone."""
    from learnwhitehack.reporting import html_export
    html_export.export(report_file, output)


# ---------------------------------------------------------------------------
# Commande : run-all
# ---------------------------------------------------------------------------

@cli.command("run-all")
@click.option("--skip", "-s", multiple=True,
              help="Modules à ignorer (ex: --skip vuln.sqli --skip vuln.lfi)")
@click.pass_context
def run_all(ctx: click.Context, skip: tuple[str, ...]) -> None:
    """Lance tous les modules de reconnaissance et de scan en séquence.

    Ordre : recon passive → WP fingerprint → WP advanced → scanner réseau → vuln
    """
    from learnwhitehack.recon import (
        well_known, rss_metadata, author_archives, headers_audit,
        ssl_audit, subdomain_enum, whois_lookup, email_harvester,
        js_analyzer, sitemap_crawler,
    )
    from learnwhitehack.wordpress import (
        fingerprint, api_users, plugin_fuzzer, xmlrpc_probe,
        config_leaks, user_bruteforce_prep,
    )
    from learnwhitehack.scanner import port_scanner, banner_grabber, tech_fingerprint, directory_enum
    from learnwhitehack.vuln import cve_search, header_injection, sqli_probe, lfi_probe

    obj = ctx.obj
    cfg = obj["cfg"]
    report = obj["report"]
    skip_set = set(skip)

    def should_run(module: str) -> bool:
        return module not in skip_set

    click.echo(f"\n[lwh] Démarrage run-all → {cfg.target.url or cfg.target.ip}\n")

    # Recon passive
    if should_run("recon.whois"):        whois_lookup.run(cfg, report)
    if should_run("recon.ssl"):          ssl_audit.run(cfg, report)
    if should_run("recon.subdomains"):   subdomain_enum.run(cfg, report)
    if should_run("recon.headers"):      headers_audit.run(cfg, report)
    if should_run("recon.sitemap"):      sitemap_crawler.run(cfg, report)
    if should_run("recon.well_known"):   well_known.run(cfg, report)
    if should_run("recon.emails"):       email_harvester.run(cfg, report)
    if should_run("recon.js"):           js_analyzer.run(cfg, report)
    if should_run("recon.rss"):          rss_metadata.run(cfg, report)

    # WordPress
    if should_run("wordpress.fingerprint"):
        fp_result = fingerprint.run(cfg, report)
    else:
        fp_result = {}

    if should_run("wordpress.api_users"):    api_users.run(cfg, report)
    if should_run("wordpress.author"):       author_archives.run(cfg, report)
    if should_run("wordpress.config_leaks"): config_leaks.run(cfg, report)
    if should_run("wordpress.xmlrpc"):       xmlrpc_probe.run(cfg, report)

    detected_plugins = fp_result.get("plugins", [])
    if should_run("wordpress.plugin_fuzz") and detected_plugins:
        plugin_fuzzer.run(cfg, report, plugins=detected_plugins)

    # Scanner réseau
    if should_run("scanner.tech"):     tech_fingerprint.run(cfg, report)
    if should_run("scanner.dir"):      directory_enum.run(cfg, report)
    if cfg.target.ip:
        if should_run("scanner.ports"):   port_scanner.run(cfg, report)
        if should_run("scanner.banners"): banner_grabber.run(cfg, report)

    # Vulnérabilités
    if should_run("vuln.headers"):   header_injection.run(cfg, report)
    if should_run("vuln.sqli"):      sqli_probe.run(cfg, report)
    if should_run("vuln.lfi"):       lfi_probe.run(cfg, report)
    if should_run("vuln.cve"):       cve_search.run(cfg, report)

    # Rapport final
    saved = report.save(cfg.output.dir, prefix="run_all")
    report.print_summary()
    click.echo(f"\nRapport JSON : {saved}")
    click.echo(f"Rapport MD   : {saved.with_suffix('.md')}")

    # Export HTML automatique
    from learnwhitehack.reporting import html_export
    html_path = html_export.export(saved)
    click.echo(f"Rapport HTML : {html_path}")

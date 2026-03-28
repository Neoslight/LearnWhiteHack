"""StealthSession — session HTTP avec rotation UA, jitter et support proxy.

Toutes les requêtes du toolkit passent par cette classe pour maximiser
la discrétion sur les cibles de test autorisées.
"""

from __future__ import annotations

import random
import warnings
from typing import Any

import requests
import urllib3

from learnwhitehack.core.rate_limiter import RateLimiter

# Pool de User-Agents réalistes (Chrome, Firefox, Safari — multi-OS, 2023-2024)
_UA_POOL = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    # Googlebot (utile pour certains tests de contenu)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

_ACCEPT_LANGUAGES = [
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8,fr;q=0.5",
    "fr-FR,fr;q=0.8,en;q=0.5",
    "en-US,en;q=0.9,fr;q=0.7",
    "de-DE,de;q=0.9,en;q=0.8",
]

_ACCEPT_HTML = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
]


class StealthSession(requests.Session):
    """Session requests avec UA rotation, jitter et proxy support.

    Usage:
        session = StealthSession(min_delay=1.0, max_delay=3.0)
        resp = session.get("https://example.com")
    """

    def __init__(
        self,
        min_delay: float = 1.0,
        max_delay: float = 3.5,
        proxies_list: list[str] | None = None,
        verify_ssl: bool = True,
        ua_pool: list[str] | None = None,
        apply_jitter: bool = True,
    ) -> None:
        super().__init__()
        self._rate_limiter = RateLimiter(min_delay, max_delay)
        self._proxies_list = proxies_list or []
        self._proxy_index = 0
        self._ua_pool = ua_pool or _UA_POOL
        self._apply_jitter = apply_jitter

        if not verify_ssl:
            self.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            warnings.warn(
                "SSL verification désactivée — à utiliser uniquement avec Burp Suite "
                "sur des cibles de test autorisées.",
                stacklevel=2,
            )

    def _rotate_ua(self) -> None:
        """Choisit un User-Agent aléatoire dans le pool."""
        self.headers.update({"User-Agent": random.choice(self._ua_pool)})

    def _randomize_headers(self) -> None:
        """Randomise les headers courants pour éviter le fingerprinting."""
        headers: dict[str, str] = {
            "Accept": random.choice(_ACCEPT_HTML),
            "Accept-Language": random.choice(_ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
        }
        # DNT aléatoire
        if random.random() > 0.5:
            headers["DNT"] = "1"
        # Cache-Control aléatoire
        if random.random() > 0.6:
            headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])
        self.headers.update(headers)

    def _rotate_proxy(self) -> None:
        """Active le prochain proxy de la liste (round-robin)."""
        if not self._proxies_list:
            return
        proxy_url = self._proxies_list[self._proxy_index % len(self._proxies_list)]
        self._proxy_index += 1
        self.proxies.update({"http": proxy_url, "https": proxy_url})

    def request(self, method: str, url: str | bytes, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        self._rotate_ua()
        self._randomize_headers()
        self._rotate_proxy()
        if self._apply_jitter:
            self._rate_limiter.wait()
        return super().request(method, url, **kwargs)


def make_session(
    min_delay: float = 1.0,
    max_delay: float = 3.5,
    proxies: list[str] | None = None,
    verify_ssl: bool = True,
    apply_jitter: bool = True,
) -> StealthSession:
    """Factory pour créer une StealthSession configurée."""
    return StealthSession(
        min_delay=min_delay,
        max_delay=max_delay,
        proxies_list=proxies,
        verify_ssl=verify_ssl,
        apply_jitter=apply_jitter,
    )

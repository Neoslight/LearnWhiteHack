"""Hiérarchie d'exceptions personnalisées pour learnwhitehack."""


class LearnWhiteHackError(Exception):
    """Exception de base du toolkit."""


class ConfigError(LearnWhiteHackError):
    """Erreur de configuration (TOML invalide, champ manquant, etc.)."""


class NetworkError(LearnWhiteHackError):
    """Erreur réseau générique."""


class ConnectionTimeout(NetworkError):
    """Timeout de connexion."""


class SSLError(NetworkError):
    """Erreur SSL/TLS."""


class ProxyError(NetworkError):
    """Erreur de proxy."""


class ModuleError(LearnWhiteHackError):
    """Erreur interne d'un module de scan."""


class ScanAborted(ModuleError):
    """Scan interrompu manuellement ou par condition d'arrêt."""


class RateLimitExceeded(ModuleError):
    """L'API distante a retourné un rate-limit (429/403)."""

"""Reglas para reconocer secretos.

Casi todas buscan formatos concretos (un token de GitHub siempre empieza por ghp_ y
tiene 36 caracteres más), que dan muy pocos falsos positivos. Las genéricas, las de
`password = "..."`, necesitan más filtros para no saltar con cualquier cosa: el valor
tiene que parecer aleatorio (entropía alta), no puede ser un ejemplo de documentación
("changeme", "your-token"), ni un nombre de variable, ni "foo:bar" en base64.
"""

from __future__ import annotations

import base64
import fnmatch
import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {1: "BAJA", 2: "MEDIA", 3: "ALTA", 4: "CRÍTICA"}[self.value]


# Valores de ejemplo que aparecen en documentación y plantillas.
PLACEHOLDERS = (
    "example", "xxxx", "changeme", "change_me", "your_", "your-", "<", "${", "{{",
    "dummy", "placeholder", "password", "passwd", "contraseña",
)  # fmt: skip


def entropy(text: str) -> float:
    """Entropía de Shannon en bits por carácter. Una palabra ronda 2-3; un token aleatorio, 4 o más."""
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    if any(p in low for p in PLACEHOLDERS) or len(set(value)) <= 3:
        return True
    # {variable} de un f-string o de una plantilla: es código, no un secreto
    return "{" in value and "}" in value


def looks_like_identifier(value: str) -> bool:
    """Palabras pegadas ("NonExpressionParenEnd", "getHTTPResponse"), no algo aleatorio."""
    words = []
    for part in re.split(r"[_.:-]+", value.strip("?$#@!_-.:*")):
        pieces = re.findall(r"[A-Z]{2,}(?![a-z])|[A-Z]?[a-z]+|\d+|.", part)
        if "".join(pieces) != part:
            return False
        words += pieces
    if not words or not all(w.isalpha() for w in words):
        return False
    # Palabras "de verdad": 3 letras o más y con alguna vocal (salvo siglas como JSX).
    # Un texto aleatorio sale troceado en pedazos cortos y sin vocales, así que tienen
    # que ser al menos dos y cubrir casi todo el texto (el "In" de "InterpolationInJSX"
    # se perdona).
    real = [w for w in words if len(w) >= 3 and (w.isupper() or re.search("[aeiouAEIOU]", w))]
    covered = sum(len(w) for w in real) / sum(len(w) for w in words)
    return len(real) >= 2 and covered >= 0.85


def decodes_to_something_trivial(value: str) -> bool:
    """Base64 de algo que no es un secreto: "Zm9vOmJhcg==" es "foo:bar".

    En las pruebas y la documentación es muy típico poner credenciales de mentira
    codificadas en base64 (el formato de la autenticación Basic).
    """
    if len(value) < 8 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        return False
    try:
        text = base64.b64decode(value + "=" * (-len(value) % 4), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    return text.isprintable() and (looks_like_placeholder(text) or entropy(text) < 3.0)


def is_fake(value: str) -> bool:
    return looks_like_placeholder(value) or looks_like_identifier(value) or decodes_to_something_trivial(value)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    pattern: re.Pattern
    min_entropy: float = 0.0  # solo para las reglas genéricas
    # Dónde buscar pistas de que es un ejemplo: "" (no se mira), "secret" (solo en el
    # valor), "match" (en todo lo encontrado, p. ej. toda la URL) o "line" (en la línea).
    fake_check: str = ""
    files: tuple[str, ...] = ()  # si no está vacío, la regla solo se aplica a estos archivos

    def applies_to(self, path: str) -> bool:
        name = path.rsplit("/", 1)[-1]
        return not self.files or any(fnmatch.fnmatch(name, pattern) for pattern in self.files)

    def find(self, line: str):
        """Devuelve (columna, secreto) por cada coincidencia válida en la línea."""
        for m in self.pattern.finditer(line):
            # Si la regla tiene un grupo, el secreto es el grupo; si no, toda la coincidencia.
            secret = m.group(m.lastindex or 0)
            if self.fake_check == "secret" and is_fake(secret):
                continue
            if self.fake_check == "match" and (is_fake(secret) or looks_like_placeholder(m.group(0))):
                continue
            if self.fake_check == "line" and looks_like_placeholder(line):
                continue
            if self.min_entropy and entropy(secret) < self.min_entropy:
                continue
            yield m.start(m.lastindex or 0) + 1, secret


def _rule(id, title, severity, regex, flags=0, **kw) -> Rule:
    return Rule(id, title, severity, re.compile(regex, flags), **kw)


# Nombres de variable que suelen guardar un secreto, con lo que lleven delante:
# DB_PASSWORD, dbPassword, SECRET_KEY, stripe_api_key...
SECRET_NAME = (
    r"\b[\w.-]*?(?:password|passwd|pwd|secret|secret_?key|api_?key|apikey|"
    r"auth_?token|access_?token|refresh_?token|client_?secret|token)\b"
)
# Archivos de configuración, donde los valores van muchas veces sin comillas.
CONFIG_FILES = (".env", ".env.*", "*.env", "*.ini", "*.cfg", "*.conf", "*.properties", "*.yml", "*.yaml")


RULES = [
    _rule(
        "private-key",
        "Clave privada",
        Severity.CRITICAL,
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        fake_check="line",  # "-----BEGIN PRIVATE KEY-----\\nXXXX..." en la documentación
    ),
    _rule(
        "aws-access-key-id",
        "ID de clave de acceso de AWS",
        Severity.HIGH,
        r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
        fake_check="secret",  # AKIAIOSFODNN7EXAMPLE sale en toda la documentación de AWS
    ),
    _rule(
        "aws-secret-access-key",
        "Clave secreta de AWS",
        Severity.CRITICAL,
        r"aws_?secret_?(?:access_?)?key\s*[:=]\s*[\"']?([A-Za-z0-9/+]{40})\b",
        re.IGNORECASE,
        fake_check="secret",
    ),
    _rule("github-token", "Token de GitHub", Severity.CRITICAL, r"\b(gh[pousr]_[A-Za-z0-9]{36})\b"),
    _rule(
        "github-fine-grained-token",
        "Token de GitHub (fine-grained)",
        Severity.CRITICAL,
        r"\b(github_pat_[A-Za-z0-9_]{82})\b",
    ),
    _rule("gitlab-token", "Token de GitLab", Severity.CRITICAL, r"\b(glpat-[A-Za-z0-9_-]{20,})\b"),
    _rule("slack-token", "Token de Slack", Severity.HIGH, r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
    _rule(
        "slack-webhook",
        "Webhook de Slack",
        Severity.MEDIUM,
        r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)",
    ),
    _rule(
        "discord-webhook",
        "Webhook de Discord",
        Severity.MEDIUM,
        r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)",
    ),
    _rule(
        "telegram-bot-token",
        "Token de bot de Telegram",
        Severity.HIGH,
        r"\b([0-9]{8,10}:AA[A-Za-z0-9_-]{33})\b",
    ),
    _rule("stripe-secret-key", "Clave secreta de Stripe", Severity.CRITICAL, r"\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b"),
    _rule("google-api-key", "Clave de API de Google", Severity.HIGH, r"\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])"),
    _rule(
        "sendgrid-api-key",
        "Clave de API de SendGrid",
        Severity.HIGH,
        r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])",
    ),
    _rule("npm-token", "Token de npm", Severity.HIGH, r"\b(npm_[A-Za-z0-9]{36})\b"),
    _rule("pypi-token", "Token de PyPI", Severity.HIGH, r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})"),
    _rule(
        "openai-api-key",
        "Clave de API de OpenAI",
        Severity.HIGH,
        r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})",
    ),
    _rule(
        "anthropic-api-key",
        "Clave de API de Anthropic",
        Severity.HIGH,
        r"\b(sk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{80,})",
    ),
    _rule(
        "jwt",
        "JSON Web Token",
        Severity.MEDIUM,
        r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
    ),
    _rule(
        "url-password",
        "Contraseña dentro de una URL",
        Severity.HIGH,
        r"\b[a-z][a-z0-9+.-]*://[^/\s:@\"']+:([^/\s:@\"']{4,})@[^\s/\"']+",
        re.IGNORECASE,
        fake_check="match",  # "your-name:abc123@..." en un README
        min_entropy=2.5,
    ),
    _rule(
        "generic-secret",
        "Posible contraseña o clave en el código",
        Severity.MEDIUM,
        SECRET_NAME + r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']",
        re.IGNORECASE,
        fake_check="secret",
        min_entropy=3.5,
    ),
    _rule(
        "generic-secret-config",
        "Posible contraseña o clave en la configuración",
        Severity.MEDIUM,
        SECRET_NAME + r"\s*[:=]\s*([^\s\"'#]{8,})\s*(?:#.*)?$",
        re.IGNORECASE,
        fake_check="secret",
        min_entropy=3.5,
        files=CONFIG_FILES,
    ),
]

RULES_BY_ID = {r.id: r for r in RULES}

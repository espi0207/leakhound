"""Busca secretos en texto, archivos y directorios."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .rules import RULES, Rule, Severity

# Carpetas que no merece la pena mirar: dependencias, entornos virtuales, compilados.
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "dist",
}  # fmt: skip
MAX_FILE_SIZE = 2 * 1024 * 1024
IGNORE_FILE = ".leakhound-ignore"
INLINE_IGNORE = "leakhound:ignore"

# Reglas genéricas: si en la misma línea ya ha saltado una concreta, sobran.
GENERIC = {
    "generic-secret", "generic-secret-config", "url-password", "url-query-password", "xml-secret",
    "authorization-header", "cli-password",
}  # fmt: skip
# Las únicas reglas en las que se enseña el dominio (el resto de la URL es el secreto).
WEBHOOKS = {"slack-webhook", "discord-webhook"}


@dataclass(frozen=True)
class Finding:
    rule: Rule
    path: str
    line: int
    column: int
    secret: str
    commit: str | None = None  # solo en el historial de git
    author: str | None = None
    date: str | None = None
    still_present: bool | None = None  # en el historial: ¿sigue en el código actual?

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    @property
    def masked(self) -> str:
        """El secreto sin enseñarlo: primeros caracteres y longitud. Un informe no debe filtrar lo que busca."""
        if self.rule.id == "private-key":
            return self.secret.split("\n", 1)[0]  # la cabecera dice qué tipo de clave es; el cuerpo no se enseña
        if self.rule.id in WEBHOOKS and "/" in self.secret[8:]:
            # En un webhook lo que identifica el servicio es el dominio; el secreto es el resto.
            host = self.secret[: self.secret.index("/", 8) + 1]
            return f"{host}… ({len(self.secret)} caracteres)"
        visible = 4 if len(self.secret) >= 16 else 2
        return f"{self.secret[:visible]}… ({len(self.secret)} caracteres)"

    @property
    def fingerprint(self) -> str:
        """Identificador estable para ignorar un hallazgo concreto en .leakhound-ignore."""
        return hashlib.sha256(f"{self.rule.id}:{self.secret}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        data = {
            "rule": self.rule.id,
            "title": self.rule.title,
            "severity": self.severity.label,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "secret": self.masked,
            "fingerprint": self.fingerprint,
        }
        if self.commit:
            data.update(commit=self.commit, author=self.author, date=self.date, still_present=self.still_present)
        return data


def scan_line(line: str, path: str = "", rules: Iterable[Rule] = RULES) -> list[tuple[Rule, int, str]]:
    if INLINE_IGNORE in line:
        return []
    hits = [(rule, col, secret) for rule in rules if rule.applies_to(path) for col, secret in rule.find(line)]
    specific = [secret for rule, _, secret in hits if rule.id not in GENERIC]
    return [
        (rule, col, secret)
        for rule, col, secret in hits
        if rule.id not in GENERIC or not any(s in secret or secret in s for s in specific)
    ]


# Una línea del cuerpo de una clave (base64 en PEM, OpenSSH y PuTTY).
KEY_BODY = re.compile(r"^[A-Za-z0-9+/=]{40,}$")
KEY_LOOKAHEAD = 8  # PuTTY pone antes "Encryption:", "Comment:" y "Public-Lines:"


def with_key_body(rule: Rule, secret: str, following: Iterable[str]) -> str:
    """En una clave privada lo que salta es la cabecera, igual en todas las del mismo tipo.

    Se le pega la primera línea del cuerpo para que cada clave tenga su propia huella: si no,
    ignorar una clave en .leakhound-ignore ignoraba todas las demás.
    """
    if rule.id != "private-key":
        return secret
    for line in following:
        if KEY_BODY.match(line.strip()):
            return f"{secret}\n{line.strip()}"
    return secret


def scan_text(text: str, path: str, first_line: int = 1) -> Iterator[Finding]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        for rule, col, secret in scan_line(line, path):
            secret = with_key_body(rule, secret, lines[index + 1 : index + 1 + KEY_LOOKAHEAD])
            yield Finding(rule, path, first_line + index, col, secret)


def is_binary(chunk: bytes) -> bool:
    return b"\0" in chunk


class Ignore:
    """Lo que hay en .leakhound-ignore: huellas de hallazgos concretos y rutas (con comodines).

    # un falso positivo que ya he revisado
    3f2a9c0d1b7e4a55
    tests/fixtures/*
    """

    def __init__(self, fingerprints: set[str] | None = None, paths: list[str] | None = None) -> None:
        self.fingerprints = fingerprints or set()
        self.paths = paths or []

    @classmethod
    def load(cls, root: Path) -> Ignore:
        file = root / IGNORE_FILE
        if not file.is_file():
            return cls()
        fingerprints, paths = set(), []
        for raw in file.read_text(encoding="utf-8").splitlines():
            entry = raw.split("#", 1)[0].strip()
            if not entry:
                continue
            if len(entry) == 16 and all(c in "0123456789abcdef" for c in entry):
                fingerprints.add(entry)
            else:
                paths.append(entry)
        return cls(fingerprints, paths)

    def skips_path(self, rel: str) -> bool:
        """Como en .gitignore: vale un comodín (tests/fixtures/*), una carpeta (tests/fixtures o
        tests/) y un nombre suelto, que cuenta esté donde esté (config.example.py, node_modules)."""
        *folders, name = rel.split("/")
        for pattern in self.paths:
            folder = pattern.rstrip("/")
            if fnmatch.fnmatch(rel, pattern) or rel.startswith(folder + "/"):
                return True
            if "/" not in folder and (fnmatch.fnmatch(name, folder) or folder in folders):
                return True
        return False

    def keeps(self, finding: Finding) -> bool:
        return finding.fingerprint not in self.fingerprints and not self.skips_path(finding.path)


UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")


def read_text_file(path: Path, errors: list | None = None, skipped: list | None = None) -> str | None:
    """Contenido del archivo si es de texto y de un tamaño razonable; si no, None.

    Si no se puede leer, se apunta en `errors`: un archivo sin leer no es un archivo limpio.
    Un archivo de texto demasiado grande (un volcado de base de datos, un log) se apunta en
    `skipped`, para que quien lo lanza sepa que eso se ha quedado sin mirar.
    """
    try:
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            with open(path, "rb") as fh:
                head = fh.read(8192)
            if skipped is not None and (head.startswith(UTF16_BOMS) or not is_binary(head)):
                skipped.append((path, f"demasiado grande: {size / 1024 / 1024:.0f} MB"))
            return None
        data = path.read_bytes()
    except OSError as exc:
        if errors is not None:
            errors.append((path, exc.strerror or str(exc)))
        return None
    # UTF-16 (lo que escribe PowerShell 5 con ">") está lleno de bytes a cero, pero es texto.
    utf16 = data.startswith(UTF16_BOMS)
    if is_binary(data[:8192]) and not utf16:
        return None
    return data.decode("utf-16" if utf16 else "utf-8", errors="replace")


def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath, name)
            if not path.is_symlink():  # un enlace podría sacarnos del directorio
                yield path


def project_root(path: Path) -> Path:
    """La raíz del repositorio git que contiene `path`, o el propio directorio si no hay ninguno.

    Así, escanear src/ usa el .leakhound-ignore de la raíz y las rutas salen como src/config.py.
    """
    start = path if path.is_dir() else path.parent
    for folder in (start, *start.parents):
        if (folder / ".git").exists():
            return folder
    return start


def _files_to_scan(root: Path) -> Iterator[Path]:
    yield from iter_files(root)
    # .git no se recorre, pero su config sí se mira: ahí se queda el token cuando se clona con
    # https://usuario:token@github.com/..., y viaja con la carpeta si se copia o se sube a un servidor.
    git_config = root / ".git" / "config"
    if root.is_dir() and git_config.is_file() and not git_config.is_symlink():
        yield git_config


def scan_path(
    root: Path, ignore: Ignore | None = None, errors: list | None = None, skipped: list | None = None
) -> list[Finding]:
    """Escanea un archivo o un directorio entero.

    Los que no se pueden leer van a `errors` y los de texto demasiado grandes, a `skipped`.
    """
    root = Path(root).resolve()
    base = project_root(root)
    ignore = ignore if ignore is not None else Ignore.load(base)
    findings = []
    for path in _files_to_scan(root):
        rel = path.relative_to(base).as_posix()
        if rel == IGNORE_FILE or ignore.skips_path(rel):
            continue
        failed: list = []
        too_big: list = []
        text = read_text_file(path, failed, too_big)
        if errors is not None:
            errors.extend((rel, reason) for _, reason in failed)
        if skipped is not None:
            skipped.extend((rel, reason) for _, reason in too_big)
        if text is None:
            continue
        findings.extend(f for f in scan_text(text, rel) if ignore.keeps(f))
    return findings

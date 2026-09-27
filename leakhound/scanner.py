"""Busca secretos en texto, archivos y directorios."""

from __future__ import annotations

import fnmatch
import hashlib
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .rules import RULES, Rule, Severity

# Carpetas que no merece la pena mirar: dependencias, entornos virtuales, compilados.
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".ruff_cache", "dist"}
MAX_FILE_SIZE = 2 * 1024 * 1024
IGNORE_FILE = ".leakhound-ignore"
INLINE_IGNORE = "leakhound:ignore"

# Reglas genéricas: si en la misma línea ya ha saltado una concreta, sobran.
GENERIC = {"generic-secret", "generic-secret-config", "url-password"}


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
        if self.secret.startswith("https://"):
            # En un webhook lo que identifica el servicio es el dominio; el secreto es el resto.
            host = self.secret[: self.secret.index("/", 8) + 1] if "/" in self.secret[8:] else self.secret
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


def scan_text(text: str, path: str, first_line: int = 1) -> Iterator[Finding]:
    for number, line in enumerate(text.splitlines(), start=first_line):
        for rule, col, secret in scan_line(line, path):
            yield Finding(rule, path, number, col, secret)


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
        return any(fnmatch.fnmatch(rel, p) for p in self.paths)

    def keeps(self, finding: Finding) -> bool:
        return finding.fingerprint not in self.fingerprints and not self.skips_path(finding.path)


def read_text_file(path: Path) -> str | None:
    """Contenido del archivo si es de texto y de un tamaño razonable; si no, None."""
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if is_binary(data[:8192]):
        return None
    return data.decode("utf-8", errors="replace")


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


def scan_path(root: Path, ignore: Ignore | None = None) -> list[Finding]:
    """Escanea un archivo o un directorio entero."""
    root = Path(root)
    base = root if root.is_dir() else root.parent
    ignore = ignore if ignore is not None else Ignore.load(base)
    findings = []
    for path in iter_files(root):
        rel = path.relative_to(base).as_posix()
        if rel == IGNORE_FILE or ignore.skips_path(rel):
            continue
        text = read_text_file(path)
        if text is None:
            continue
        findings.extend(f for f in scan_text(text, rel) if ignore.keeps(f))
    return findings

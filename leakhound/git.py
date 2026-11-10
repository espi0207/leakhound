"""Buscar secretos en el historial de git y en los cambios preparados para commit.

Lo importante del historial: borrar una contraseña del código y hacer commit no la
quita del repositorio. Sigue en el commit donde se añadió y cualquiera que clone el
repo puede verla con `git log -p`. Por eso aquí se lee el historial entero.
"""

from __future__ import annotations

import codecs
import os
import re
import stat
import subprocess
import sys
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import replace
from pathlib import Path

from .scanner import KEY_LOOKAHEAD, Finding, Ignore, scan_line, scan_path, with_key_body

COMMIT_MARK = "\x00COMMIT "  # un NUL no puede salir en el diff de un archivo de texto
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
HOOK_MARK = "# instalado por leakhound"
# Con diff.noprefix=true en la configuración del usuario, git quita el "b/" y la ruta
# saldría cortada ("ADME.md"). Así siempre lleva los prefijos que se esperan.
DIFF_PREFIXES = ("--src-prefix=a/", "--dst-prefix=b/")


# En Windows, desde la ventana (que no tiene consola), cada llamada a git abriría una
# consola negra un instante. Esta opción lo evita; en los demás sistemas no existe.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class GitError(Exception):
    pass


def _git(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            encoding="utf-8",  # git habla UTF-8 aunque Windows use otra codificación por defecto
            errors="replace",
            check=False,
            creationflags=NO_WINDOW,
        )
    except FileNotFoundError as exc:
        raise GitError("no encuentro el comando git") from exc
    if result.returncode != 0:
        raise GitError(result.stderr.strip() or f"git {args[0]} ha fallado")
    return result.stdout


def repo_root(path: Path) -> Path:
    return Path(_git(path, "rev-parse", "--show-toplevel").strip())


def _unquote(path: str) -> str:
    # git entrecomilla las rutas con caracteres raros ("b/con\ttab.txt") y los escapa como
    # en C, a veces en octal (\303\261 es una ñ). escape_decode lo deshace sobre los bytes.
    if path.startswith('"') and path.endswith('"'):
        return codecs.escape_decode(path[1:-1].encode())[0].decode("utf-8", errors="replace")
    return path


def added_lines(diff: Iterable[str]) -> Iterator[tuple[dict, str, int, str]]:
    """Recorre la salida de `git log -p` o `git diff` y devuelve las líneas añadidas.

    Da (commit, ruta, número de línea, texto). `commit` es un dict con hash, autor y
    fecha, vacío si el diff no viene de git log.
    """
    commit: dict = {}
    path = None
    in_header = False
    line_no = 0
    for raw in diff:
        line = raw.rstrip("\n")
        if line.startswith(COMMIT_MARK):
            sha, author, date = (line[len(COMMIT_MARK) :].split("\t") + ["", ""])[:3]
            commit = {"commit": sha, "author": author, "date": date}
            path, in_header = None, False
        elif line.startswith("diff --git "):
            path, in_header = None, True
        elif in_header and line.startswith("+++ "):
            target = _unquote(line[4:])
            path = None if target == "/dev/null" else target[2:]  # quita el "b/"
        elif m := HUNK.match(line):
            in_header = False
            line_no = int(m.group(1))
        elif not in_header and path and line.startswith("+"):
            yield commit, path, line_no, line[1:]
            line_no += 1
        elif not in_header and line.startswith(" "):
            line_no += 1  # línea de contexto (diff.interHunkContext puede meterlas aunque sea --unified=0)


def _with_lookahead(items: Iterator[tuple], n: int) -> Iterator[tuple[tuple, list[tuple]]]:
    """Cada elemento junto con los `n` siguientes (sin cargar el diff entero en memoria)."""
    window: deque = deque()
    for item in items:
        window.append(item)
        if len(window) > n:
            yield window[0], list(window)[1:]
            window.popleft()
    while window:
        yield window[0], list(window)[1:]
        window.popleft()


def _scan_diff(diff: Iterable[str], ignore: Ignore) -> list[Finding]:
    findings = []
    for (commit, path, line_no, text), following in _with_lookahead(added_lines(diff), KEY_LOOKAHEAD):
        for rule, col, secret in scan_line(text, path):
            # el cuerpo de una clave son las líneas que siguen en el mismo archivo y el mismo commit
            body = [t for c, p, _, t in following if c is commit and p == path]
            secret = with_key_body(rule, secret, body)
            finding = Finding(rule, path, line_no, col, secret, **commit)
            if ignore.keeps(finding):
                findings.append(finding)
    return findings


def _log_and_scan(root: Path, ignore: Ignore, merges: str) -> list[Finding] | None:
    """`git log -p` de todas las ramas, escaneado sobre la marcha. None si aún no hay commits."""
    cmd = [
        "git", "-C", str(root), "-c", "core.quotepath=false",
        "log", "--all", "-p", merges, "--unified=0", "--no-color", "--no-ext-diff", *DIFF_PREFIXES,
        "--format=%x00COMMIT %H%x09%an%x09%as",  # %x00 lo pone git: no se puede pasar un NUL como argumento
    ]  # fmt: skip
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=NO_WINDOW) as proc:
        lines = (raw.decode("utf-8", errors="replace") for raw in proc.stdout)
        findings = _scan_diff(lines, ignore)
        stderr = proc.stderr.read().decode(errors="replace")
    if proc.returncode != 0:
        if "does not have any commits" in stderr:
            return None
        raise GitError(stderr.strip() or "git log ha fallado")
    return findings


def scan_history(repo: Path) -> list[Finding]:
    """Todos los secretos que se han añadido alguna vez en cualquier rama."""
    root = repo_root(repo)
    ignore = Ignore.load(root)
    # Sin esto, git log no enseña el diff de los merges, y lo que se escribe al resolver un
    # conflicto no aparece en ningún commit. Contra el primer padre sale justo lo que el
    # merge cambió en la rama principal. --diff-merges es de git 2.31; con uno más viejo, -m.
    try:
        findings = _log_and_scan(root, ignore, "--diff-merges=first-parent")
    except GitError as exc:
        if "diff-merges" not in str(exc):
            raise
        findings = _log_and_scan(root, ignore, "-m")
    if findings is None:
        return []

    # git log va del commit más nuevo al más viejo; me quedo con el primero que lo añadió.
    oldest: dict[tuple, Finding] = {}
    for f in findings:
        oldest[(f.rule.id, f.secret, f.path)] = f
    present = {(f.rule.id, f.secret) for f in scan_path(root, ignore)}
    return [replace(f, still_present=(f.rule.id, f.secret) in present) for f in oldest.values()]


def scan_staged(repo: Path) -> list[Finding]:
    """Los secretos en lo que está preparado para el próximo commit (`git add`)."""
    root = repo_root(repo)
    diff = _git(
        root, "-c", "core.quotepath=false", "diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff",
        *DIFF_PREFIXES,
    )  # fmt: skip
    return _scan_diff(diff.splitlines(), Ignore.load(root))


def hooks_dir(repo: Path) -> Path:
    root = repo_root(repo)
    hooks = Path(_git(root, "rev-parse", "--git-path", "hooks").strip())
    return hooks if hooks.is_absolute() else root / hooks


# Si el Python con el que se instaló ya no tiene leakhound (se borró el entorno virtual, se
# desinstaló...), git decía solo "No module named leakhound" y no dejaba hacer ningún commit.
HOOK_SCRIPT = """#!/bin/sh
{mark}
if ! "{python}" -c "import leakhound" 2>/dev/null; then
    echo "leakhound: este hook usa {python}, que ya no tiene leakhound." >&2
    echo "Vuelve a ponerlo con 'leakhound hook install' o quita el archivo $0." >&2
    echo "Para hacer este commit sin revisar: git commit --no-verify" >&2
    exit 1
fi
exec "{python}" -m leakhound staged
"""


def install_hook(repo: Path, force: bool = False) -> Path:
    hook = hooks_dir(repo) / "pre-commit"
    if hook.exists() and HOOK_MARK not in hook.read_text(errors="replace") and not force:
        raise GitError(f"ya hay un hook pre-commit en {hook} que no es mío; usa --force para reemplazarlo")
    hook.parent.mkdir(parents=True, exist_ok=True)
    # Con la ruta completa de este Python, el hook funciona aunque el entorno virtual no esté activado.
    hook.write_text(HOOK_SCRIPT.format(mark=HOOK_MARK, python=sys.executable), encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook


def uninstall_hook(repo: Path) -> Path | None:
    hook = hooks_dir(repo) / "pre-commit"
    if hook.exists() and HOOK_MARK in hook.read_text(errors="replace"):
        os.remove(hook)
        return hook
    return None

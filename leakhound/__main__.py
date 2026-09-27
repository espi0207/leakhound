"""Línea de comandos: leakhound scan | history | staged | hook | rules | demo."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .ansi import paint
from .git import GitError, install_hook, scan_history, scan_staged, uninstall_hook
from .report import to_json, to_sarif, to_text
from .rules import RULES
from .scanner import IGNORE_FILE, INLINE_IGNORE, scan_path

EXIT_OK, EXIT_FOUND, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="leakhound", description="Busca secretos en el código y en el historial de git")
    p.add_argument("--version", action="version", version=f"leakhound {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def output_options(cmd):
        cmd.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="formato de salida")
        cmd.add_argument("--output", "-o", type=Path, help="guardar el informe en un archivo")

    scan = sub.add_parser("scan", help="escanea archivos o directorios")
    scan.add_argument("paths", nargs="*", type=Path, default=[Path(".")])
    output_options(scan)

    history = sub.add_parser("history", help="escanea todo el historial de un repositorio git")
    history.add_argument("repo", nargs="?", type=Path, default=Path("."))
    output_options(history)

    staged = sub.add_parser("staged", help="escanea lo preparado para el próximo commit (lo usa el hook)")
    staged.add_argument("repo", nargs="?", type=Path, default=Path("."))

    hook = sub.add_parser("hook", help="instala o quita el hook pre-commit")
    hook.add_argument("action", choices=["install", "uninstall"])
    hook.add_argument("repo", nargs="?", type=Path, default=Path("."))
    hook.add_argument("--force", action="store_true", help="reemplazar un hook pre-commit que ya exista")

    sub.add_parser("rules", help="lista las reglas")
    sub.add_parser("demo", help="demostración con un repositorio temporal")
    return p


def _report(findings, fmt: str, output: Path | None, where: str) -> int:
    if fmt == "json":
        rendered = to_json(findings)
    elif fmt == "sarif":
        rendered = to_sarif(findings)
    else:
        rendered = to_text(findings, where)
    if output:
        output.write_text(rendered + "\n", encoding="utf-8")
        print(f"{len(findings)} hallazgo(s), informe guardado en {output}", file=sys.stderr)
    else:
        print(rendered)
    return EXIT_FOUND if findings else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "demo":
            from .demo import run_demo

            return run_demo()

        if args.command == "rules":
            for rule in RULES:
                print(f"{rule.id:<28} {rule.severity.label:<8} {rule.title}")
            return EXIT_OK

        if args.command == "scan":
            missing = [str(p) for p in args.paths if not p.exists()]
            if missing:
                print(f"error: no existe {', '.join(missing)}", file=sys.stderr)
                return EXIT_ERROR
            findings = [f for path in args.paths for f in scan_path(path)]
            where = ", ".join("el directorio actual" if str(p) == "." else str(p) for p in args.paths)
            return _report(findings, args.format, args.output, where)

        if args.command == "history":
            return _report(scan_history(args.repo), args.format, args.output, "el historial")

        if args.command == "staged":
            findings = scan_staged(args.repo)
            if not findings:
                return EXIT_OK
            print(to_text(findings, "los cambios preparados"), file=sys.stderr)
            print(
                paint("\nCommit cancelado.", "bold", "bright_red")
                + f" Si es un falso positivo, pon '{INLINE_IGNORE}' en esa línea o añade su huella a"
                f" {IGNORE_FILE}. Para saltarte la comprobación una vez: git commit --no-verify",
                file=sys.stderr,
            )
            return EXIT_FOUND

        if args.command == "hook":
            if args.action == "install":
                hook = install_hook(args.repo, force=args.force)
                print(f"hook instalado en {hook}: cada commit se revisará antes de hacerse")
            else:
                hook = uninstall_hook(args.repo)
                print(f"hook quitado de {hook}" if hook else "no había ningún hook de leakhound")
            return EXIT_OK
    except GitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"error: {exc.strerror or exc} ({exc.filename})", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

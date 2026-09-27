"""Colores para la terminal sin depender de colorama ni rich.

Si la salida no es una terminal (por ejemplo `> informe.txt`) o existe NO_COLOR
(https://no-color.org) no se pinta nada. FORCE_COLOR obliga a pintar.
"""

from __future__ import annotations

import os
import sys

CODES = {
    "bold": "1",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "gray": "90",
    "bright_red": "91",
}

if os.name == "nt":
    os.system("")  # truco conocido: activa las secuencias ANSI en la consola de Windows


def enabled(stream=None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


def paint(text: str, *styles: str, stream=None) -> str:
    if not styles or not enabled(stream):
        return text
    return f"\033[{';'.join(CODES[s] for s in styles)}m{text}\033[0m"


def clean(text: str) -> str:
    """Escapa los caracteres no imprimibles antes de sacar algo por pantalla.

    Las rutas y los autores de los commits pueden llevar secuencias ANSI; así se ven
    como texto en vez de mover el cursor o borrar líneas.
    """
    if text.isprintable():
        return text
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in text)

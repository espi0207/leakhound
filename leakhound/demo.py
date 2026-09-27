"""`leakhound demo`: un repositorio de mentira donde alguien sube credenciales y luego las "borra".

La demo de la terminal lo crea en un directorio temporal que se elimina al acabar. La
ventana usa el mismo repositorio (build_repo) para su "Probar con un ejemplo".
"""

from __future__ import annotations

import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from .ansi import paint
from .fakes import Fakes
from .git import NO_WINDOW, scan_history
from .report import to_text
from .scanner import scan_path


def _git(*args: str) -> None:
    subprocess.run(["git", *args], check=True, capture_output=True, creationflags=NO_WINDOW)


def _commit(repo: Path, message: str, author: str) -> None:
    _git("-C", str(repo), "add", "-A")
    _git(
        "-C", str(repo),
        "-c", f"user.name={author}", "-c", f"user.email={author.lower()}@example.com",
        "-c", "commit.gpgsign=false",
        "commit", "-q", "-m", message,
    )  # fmt: skip


def _quiet(*_: object) -> None:
    pass


def build_repo(parent: Path, step: Callable = _quiet, note: Callable = _quiet) -> Path:
    """Crea en `parent` el repositorio "tienda" con sus tres commits y devuelve su ruta.
    `step` y `note` reciben lo que va pasando, para contarlo por pantalla."""
    fake = Fakes(seed=7)
    repo = parent / "tienda"
    repo.mkdir()
    _git("init", "-q", str(repo))

    step(1, "Ana sube la configuración con las credenciales dentro")
    (repo / "settings.py").write_text(
        f'DATABASE_URL = "{fake.database_url()}"\n'
        f'AWS_ACCESS_KEY_ID = "{fake.aws_key_id()}"\n'
        f'AWS_SECRET_ACCESS_KEY = "{fake.aws_secret()}"\n',
        encoding="utf-8",
    )
    _commit(repo, "Configuración inicial", "Ana")
    note("settings.py con la URL de la base de datos y las claves de AWS")

    step(2, "Alguien se da cuenta y las cambia por variables de entorno")
    (repo / "settings.py").write_text(
        'import os\n\nDATABASE_URL = os.environ["DATABASE_URL"]\n'
        'AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\n'
        'AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]\n',
        encoding="utf-8",
    )
    _commit(repo, "Quitar credenciales del código", "Luis")
    note("el código ya no tiene ninguna contraseña... aparentemente")

    step(3, "Más tarde, un script de despliegue con un webhook y un token")
    (repo / "deploy.sh").write_text(
        "#!/bin/sh\n"
        f'curl -X POST -d "desplegado" {fake.slack_webhook()}\n'
        f'GITHUB_TOKEN="{fake.github_token()}" ./publicar.sh\n',
        encoding="utf-8",
    )
    _commit(repo, "Script de despliegue", "Ana")
    return repo


def _step(n: int, text: str) -> None:
    print()
    print(paint(f"{n}. {text}", "bold", "cyan"))
    time.sleep(0.2)


def _note(text: str) -> None:
    print(f"   {text}")


def run_demo() -> int:
    print(paint("leakhound: demostración con un repositorio de prueba", "bold"))
    # ignore_cleanup_errors: en Windows git deja archivos de solo lectura que no se dejan borrar.
    with tempfile.TemporaryDirectory(prefix="leakhound-demo-", ignore_cleanup_errors=True) as tmp:
        repo = build_repo(Path(tmp), _step, _note)

        _step(4, "leakhound scan: lo que hay ahora mismo en el código")
        print(to_text(scan_path(repo), "el código actual"))

        _step(5, "leakhound history: todo lo que ha pasado por git")
        print(to_text(scan_history(repo), "el historial"))

    print()
    print(paint("Repositorio temporal borrado.", "green"))
    return 0

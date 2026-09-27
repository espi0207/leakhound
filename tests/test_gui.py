import os
import shutil
import sys

import pytest

tk = pytest.importorskip("tkinter")

from leakhound import gui  # noqa: E402


@pytest.mark.skipif(
    sys.platform.startswith("linux") and not os.environ.get("DISPLAY"),
    reason="en Linux hace falta una pantalla (en la CI, xvfb-run)",
)
@pytest.mark.skipif(shutil.which("git") is None, reason="el ejemplo es un repositorio de git")
def test_la_ventana_funciona():
    # Lo mismo que hace la CI con el programa ya instalado: abrir la ventana con el repositorio de ejemplo
    # y comprobar que salen los cinco secretos.
    assert gui.self_check() == 0

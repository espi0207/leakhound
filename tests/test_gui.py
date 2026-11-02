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


def test_search_in_a_subfolder_points_to_the_real_files(tmp_path):
    from leakhound.fakes import Fakes
    from leakhound.gui import search

    (tmp_path / ".git").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.py").write_text(f'T = "{Fakes(seed=2).github_token()}"\n')
    result = search(tmp_path / "src", history=False)
    [finding] = result.findings
    assert (result.base / finding.path).is_file()

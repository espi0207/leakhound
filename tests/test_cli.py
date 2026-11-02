import json
import shutil

import pytest

from leakhound.__main__ import EXIT_ERROR, EXIT_FOUND, EXIT_OK, main
from leakhound.fakes import Fakes
from leakhound.rules import RULES

fake = Fakes(seed=5)


@pytest.fixture
def project(tmp_path):
    (tmp_path / "app.py").write_text(f'KEY = "{fake.stripe_key()}"\nDEBUG = True\n')
    return tmp_path


def test_scan_exit_codes(project, tmp_path, capsys):
    assert main(["scan", str(project)]) == EXIT_FOUND
    out = capsys.readouterr().out
    assert "Clave secreta de Stripe" in out and "app.py:1" in out
    clean = tmp_path / "limpio"
    clean.mkdir()
    assert main(["scan", str(clean)]) == EXIT_OK
    assert main(["scan", str(tmp_path / "no-existe")]) == EXIT_ERROR


def test_json_output(project, capsys):
    main(["scan", str(project), "--format", "json"])
    [finding] = json.loads(capsys.readouterr().out)
    assert finding["rule"] == "stripe-secret-key" and finding["severity"] == "CRÍTICA"
    assert finding["secret"].endswith("caracteres)")


def test_sarif_output(project, tmp_path, capsys):
    out = tmp_path / "leakhound.sarif"
    assert main(["scan", str(project), "--format", "sarif", "-o", str(out)]) == EXIT_FOUND
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {r.id for r in RULES}
    [result] = run["results"]
    assert result["ruleId"] == "stripe-secret-key" and result["level"] == "error"
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app.py" and location["region"]["startLine"] == 1
    assert "partialFingerprints" in result


def test_the_secret_never_reaches_any_output(project, capsys):
    secret = (project / "app.py").read_text().split('"')[1]
    for fmt in ("text", "json", "sarif"):
        main(["scan", str(project), "--format", fmt])
        assert secret not in capsys.readouterr().out


def test_rules_command(capsys):
    assert main(["rules"]) == EXIT_OK
    assert "github-token" in capsys.readouterr().out


def test_history_outside_a_repo(tmp_path, capsys):
    assert main(["history", str(tmp_path)]) == EXIT_ERROR
    assert "error" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("git") is None, reason="hace falta git")
def test_demo(capsys):
    assert main(["demo"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "ya no está en el código, pero sí en el historial" in out


def test_scan_with_unreadable_files_is_not_reported_as_clean(tmp_path, capsys, monkeypatch):
    from pathlib import Path as P

    from leakhound.__main__ import EXIT_ERROR, main

    (tmp_path / "a.txt").write_text("nada\n")
    real = P.read_bytes

    def broken(self):
        if self.name == "a.txt":
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(P, "read_bytes", broken)
    assert main(["scan", str(tmp_path)]) == EXIT_ERROR
    assert "no se ha podido leer" in capsys.readouterr().err


def test_baseline_only_reports_new_secrets(tmp_path, capsys):
    import json

    from leakhound.__main__ import EXIT_FOUND, EXIT_OK, main
    from leakhound.fakes import Fakes

    f = Fakes(seed=11)
    project = tmp_path / "p"
    project.mkdir()
    (project / "viejo.py").write_text(f'T = "{f.github_token()}"\n')
    base = tmp_path / "base.json"
    assert main(["scan", str(project), "--format", "json", "-o", str(base)]) == EXIT_FOUND
    assert main(["scan", str(project), "--baseline", str(base)]) == EXIT_OK  # lo de antes ya está apuntado

    (project / "nuevo.py").write_text(f'K = "{f.stripe_key()}"\n')
    capsys.readouterr()
    assert main(["scan", str(project), "--baseline", str(base), "--format", "json"]) == EXIT_FOUND
    assert [x["path"] for x in json.loads(capsys.readouterr().out)] == ["nuevo.py"]


def test_bad_baseline_is_an_error(tmp_path, capsys):
    from leakhound.__main__ import EXIT_ERROR, main

    bad = tmp_path / "base.json"
    bad.write_text("esto no es json")
    assert main(["scan", str(tmp_path), "--baseline", str(bad)]) == EXIT_ERROR
    assert "baseline" in capsys.readouterr().err

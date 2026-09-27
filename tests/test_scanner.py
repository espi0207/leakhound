import os
from pathlib import Path

import pytest

import leakhound
from leakhound.fakes import Fakes
from leakhound.scanner import MAX_FILE_SIZE, Ignore, scan_path

fake = Fakes(seed=3)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proyecto"
    (root / "src").mkdir(parents=True)
    (root / "src" / "config.py").write_text(f'API = "https://api.example.com"\nTOKEN = "{fake.github_token()}"\n')
    (root / "README.md").write_text("Nada que ver aquí.\n")
    return root


def test_finds_secret_with_path_and_line(project):
    [finding] = scan_path(project)
    assert finding.rule.id == "github-token"
    assert finding.path == "src/config.py" and finding.line == 2


def test_skips_git_dependencies_and_binaries(project):
    for folder in (".git", "node_modules", ".venv"):
        (project / folder).mkdir()
        (project / folder / "x.txt").write_text(f"key={fake.stripe_key()}\n")
    (project / "imagen.png").write_bytes(b"\x89PNG\0\0" + fake.stripe_key().encode())
    assert [f.path for f in scan_path(project)] == ["src/config.py"]


def test_skips_huge_files(project):
    (project / "dump.sql").write_text("x" * MAX_FILE_SIZE + f"\n{fake.stripe_key()}\n")
    assert [f.path for f in scan_path(project)] == ["src/config.py"]


@pytest.mark.skipif(os.name == "nt", reason="enlaces simbólicos")
def test_does_not_follow_symlinks(project, tmp_path):
    outside = tmp_path / "fuera.txt"
    outside.write_text(f"{fake.stripe_key()}\n")
    os.symlink(outside, project / "enlace.txt")
    assert [f.path for f in scan_path(project)] == ["src/config.py"]


def test_scan_a_single_file(project):
    [finding] = scan_path(project / "src" / "config.py")
    assert finding.path == "config.py"


def test_ignore_file_by_fingerprint_and_path(project):
    [finding] = scan_path(project)
    (project / ".leakhound-ignore").write_text(f"# ya revisado\n{finding.fingerprint}\n")
    assert scan_path(project) == []

    (project / "tests").mkdir()
    (project / "tests" / "fixture.py").write_text(f'KEY = "{fake.stripe_key()}"\n')
    (project / ".leakhound-ignore").write_text("tests/*\n")
    assert [f.path for f in scan_path(project)] == ["src/config.py"]


def test_report_never_contains_the_whole_secret(project):
    [finding] = scan_path(project)
    assert finding.secret not in finding.masked
    assert finding.secret not in str(finding.to_dict())
    assert finding.masked.startswith("ghp_")


def test_masked_webhook_shows_the_service():
    project_file = Path(__file__)  # cualquier ruta sirve, solo se usa el texto
    from leakhound.scanner import scan_text

    [finding] = scan_text(f"url = {fake.slack_webhook()}", str(project_file))
    assert finding.masked.startswith("https://hooks.slack.com/…")


def test_ignore_default_is_empty(tmp_path):
    ignore = Ignore.load(tmp_path)
    assert ignore.fingerprints == set() and ignore.paths == []


def test_leakhound_does_not_find_secrets_in_itself():
    # Las pruebas y la demo montan los secretos al ejecutarse; en el código no hay ninguno.
    root = Path(leakhound.__file__).resolve().parent.parent
    assert scan_path(root) == []

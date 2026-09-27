import os
import shutil
import subprocess

import pytest

from leakhound.fakes import Fakes
from leakhound.git import GitError, added_lines, install_hook, scan_history, scan_staged, uninstall_hook

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="hace falta git")
fake = Fakes(seed=9)


def git(repo, *args, check=True):
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=Ana", "-c", "user.email=ana@example.com",
         "-c", "commit.gpgsign=false", *args],
        capture_output=True, text=True, check=check,
    )  # fmt: skip


@pytest.fixture
def repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    return repo


def commit(repo, files: dict, message="cambio"):
    for name, content in files.items():
        path = repo / name
        if content is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def test_secret_removed_from_code_is_still_in_history(repo):
    key = fake.stripe_key()
    first = commit(repo, {"pago.py": f'STRIPE = "{key}"\n'}, "pagos")
    commit(repo, {"pago.py": 'import os\nSTRIPE = os.environ["STRIPE"]\n'}, "quitar la clave")

    [finding] = scan_history(repo)
    assert finding.rule.id == "stripe-secret-key"
    assert finding.commit == first and finding.author == "Ana"
    assert finding.path == "pago.py" and finding.line == 1
    assert finding.still_present is False


def test_history_reports_the_commit_that_added_it(repo):
    token = fake.github_token()
    first = commit(repo, {"a.sh": f"export T={token}\n"})
    commit(repo, {"b.txt": "otra cosa\n"})
    [finding] = scan_history(repo)
    assert finding.commit == first and finding.still_present is True


def test_history_covers_all_branches(repo):
    commit(repo, {"README": "hola\n"})
    git(repo, "checkout", "-q", "-b", "experimento")
    commit(repo, {"x.env": f"KEY={fake.stripe_key()}\n"})
    git(repo, "checkout", "-q", "-")
    assert [f.path for f in scan_history(repo)] == ["x.env"]


def test_line_numbers_in_the_middle_of_a_file(repo):
    commit(repo, {"cfg.ini": "a=1\nb=2\nc=3\n"})
    commit(repo, {"cfg.ini": f"a=1\nb=2\ntoken={fake.github_token()}\nc=3\n"})
    [finding] = scan_history(repo)
    assert finding.line == 3


def test_strange_file_names(repo):
    commit(repo, {"año\tnuevo.txt": f"{fake.github_token()}\n"})
    [finding] = scan_history(repo)
    assert finding.path == "año\tnuevo.txt"


def test_empty_repo_and_not_a_repo(repo, tmp_path):
    assert scan_history(repo) == []
    with pytest.raises(GitError):
        scan_history(tmp_path)


def test_staged_only_looks_at_what_is_staged(repo):
    commit(repo, {"README": "hola\n"})
    (repo / "staged.py").write_text(f'K = "{fake.stripe_key()}"\n')
    (repo / "sin_add.py").write_text(f'K = "{fake.stripe_key()}"\n')
    git(repo, "add", "staged.py")
    assert [f.path for f in scan_staged(repo)] == ["staged.py"]


def test_added_lines_ignores_file_headers():
    # Una línea añadida que empieza por "++" no es la cabecera "+++ b/...".
    diff = [
        "diff --git a/x b/x",
        "--- a/x",
        "+++ b/x",
        "@@ -0,0 +1,2 @@",
        "+++contador",
        "+normal",
    ]
    assert [(p, n, t) for _, p, n, t in added_lines(diff)] == [("x", 1, "++contador"), ("x", 2, "normal")]


@pytest.mark.skipif(os.name == "nt", reason="hooks de git en POSIX")
def test_hook_blocks_a_commit_with_a_secret(repo):
    hook = install_hook(repo)
    assert os.access(hook, os.X_OK)
    (repo / "config.py").write_text(f'TOKEN = "{fake.github_token()}"\n')
    git(repo, "add", "config.py")
    result = git(repo, "commit", "-m", "config", check=False)
    assert result.returncode != 0
    assert "Commit cancelado" in result.stderr

    (repo / "config.py").write_text('TOKEN = os.environ["TOKEN"]\n')
    git(repo, "add", "config.py")
    assert git(repo, "commit", "-q", "-m", "config", check=False).returncode == 0


def test_hook_does_not_replace_someone_elses(repo):
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-commit").write_text("#!/bin/sh\nmake lint\n")
    with pytest.raises(GitError, match="no es mío"):
        install_hook(repo)
    assert uninstall_hook(repo) is None  # tampoco lo borra
    install_hook(repo, force=True)
    assert uninstall_hook(repo) is not None
    assert not (hooks / "pre-commit").exists()

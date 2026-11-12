"""Repaso del 10 de noviembre: secretos que se daban por ejemplos, archivos que no se miraban y tipos nuevos.

Los secretos se montan por partes (ver leakhound/fakes.py): en el código no hay ninguno entero.
"""

import random
import string

import pytest

from leakhound.fakes import Fakes
from leakhound.git import install_hook
from leakhound.rules import RULES_BY_ID
from leakhound.scanner import MAX_FILE_SIZE, scan_line, scan_path

fake = Fakes(seed=11)
rng = random.Random(11)
LOWER_DIGITS = string.ascii_lowercase + string.digits
ALNUM = string.ascii_letters + string.digits


def rand(n: int, alphabet: str = ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def ids(line: str, path: str = "config.py") -> list[str]:
    return [rule.id for rule, _, _ in scan_line(line, path)]


# Contraseñas de verdad que se tomaban por ejemplos


def test_password_with_angle_bracket_or_braces_is_not_a_placeholder():
    for value in ("k9" + "<" + "3Jd8#mQz!7Rw", "aK9" + "{" + "x2mQ7!vB" + "}" + "4tLp", "Zq7<mK2#p>L9xW4"[::-1]):
        assert ids(f'DB_PASSWORD = "{value}"') == ["generic-secret"], value


def test_real_placeholders_are_still_ignored():
    for value in ("<tu-contraseña-aquí>", "{db_password}", "${DB_PASSWORD}", "{{ secrets.DB }}", "<YOUR_API_KEY_HERE>"):
        assert ids(f'DB_PASSWORD = "{value}"') == [], value


# Archivos que no se miraban


def test_utf16_file_is_scanned(tmp_path):
    # PowerShell 5 escribe así con ">": antes se tomaba por binario y no se miraba.
    (tmp_path / "salida.txt").write_bytes(f'TOKEN = "{fake.github_token()}"\r\n'.encode("utf-16"))
    [finding] = scan_path(tmp_path)
    assert finding.rule.id == "github-token" and finding.line == 1


def test_file_too_big_to_scan_is_reported(tmp_path):
    (tmp_path / "volcado.sql").write_text("-- datos\n" * (MAX_FILE_SIZE // 9 + 10))
    errors: list = []
    skipped: list = []
    assert scan_path(tmp_path, errors=errors, skipped=skipped) == []
    [(path, reason)] = skipped
    assert path == "volcado.sql" and "grande" in reason and errors == []


def test_big_binary_files_are_not_reported_as_unscanned(tmp_path):
    (tmp_path / "video.mp4").write_bytes(b"\0\1\2\3" * (MAX_FILE_SIZE // 4 + 10))
    skipped: list = []
    assert scan_path(tmp_path, skipped=skipped) == [] and skipped == []


def test_token_in_the_remote_url_of_git_config_is_found(tmp_path):
    (tmp_path / ".git").mkdir()
    url = "https://ana:" + fake.github_token() + "@github.com/ana/proyecto.git"
    (tmp_path / ".git" / "config").write_text(f'[remote "origin"]\n\turl = {url}\n')
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    [finding] = scan_path(tmp_path)
    assert finding.rule.id == "github-token" and finding.path == ".git/config"


# .leakhound-ignore


@pytest.fixture
def project(tmp_path):
    for rel in ("tests/fixtures/datos.py", "src/config.example.py", "src/config.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(f'TOKEN = "{fake.github_token()}"\n')
    return tmp_path


def test_ignore_file_accepts_a_folder_name(project):
    (project / ".leakhound-ignore").write_text("tests/fixtures\n")
    assert sorted(f.path for f in scan_path(project)) == ["src/config.example.py", "src/config.py"]


def test_ignore_file_accepts_a_file_name_anywhere(project):
    (project / ".leakhound-ignore").write_text("config.example.py\ntests/\n")
    assert [f.path for f in scan_path(project)] == ["src/config.py"]


# Tipos nuevos


def test_authorization_header_with_a_token():
    token = rand(40)
    assert ids('headers = {"Authorization": "Bearer ' + token + '"}') == ["authorization-header"]
    assert ids("curl -H 'Authorization: Bearer " + token + "' https://api.interna/v1", "deploy.sh") == [
        "authorization-header"
    ]
    assert ids('"Authorization": "Bearer " + token') == []
    assert ids("Authorization: Bearer <token>", "README.md") == []
    assert ids("Authorization: Bearer $API_TOKEN", "deploy.sh") == []


def test_password_on_a_command_line():
    password = rand(14)
    assert ids(f"mysqldump -u root --password={password} tienda > copia.sql", "copia.sh") == ["cli-password"]
    assert ids(f"sshpass -p '{password}' ssh root@servidor", "copia.sh") == ["cli-password"]
    assert ids('mysqldump -u root --password="$DB_PASS" tienda', "copia.sh") == []
    assert ids("docker login --password-stdin", "copia.sh") == []


def test_wireguard_private_key():
    key = rand(43, ALNUM + "+/") + "="
    assert ids(f"PrivateKey = {key}", "wg0.conf") == ["wireguard-private-key"]
    assert ids(f"PublicKey = {key}", "wg0.conf") == []


NEW_TOKENS = {
    "tailscale-key": lambda: "tsk" + "ey-auth-" + rand(12) + "CNTRL-" + rand(32),
    "vault-token": lambda: "hv" + "s." + rand(95),
    "sentry-token": lambda: "sntr" + "yu_" + rand(64, "0123456789abcdef"),
    "linear-api-key": lambda: "lin_" + "api_" + rand(40),
    "notion-token": lambda: "nt" + "n_" + rand(46),
    "groq-api-key": lambda: "gs" + "k_" + rand(52),
    "xai-api-key": lambda: "xa" + "i-" + rand(80),
    "replicate-token": lambda: "r" + "8_" + rand(37),
    "heroku-token": lambda: "HR" + "KU-" + rand(60),
    "doppler-token": lambda: "d" + "p.pt." + rand(43),
    "figma-token": lambda: "fig" + "d_" + rand(40),
    "pulumi-token": lambda: "pu" + "l-" + rand(40, "0123456789abcdef"),
}


@pytest.mark.parametrize("rule_id", sorted(NEW_TOKENS))
def test_new_token_types(rule_id):
    token = NEW_TOKENS[rule_id]()
    assert rule_id in RULES_BY_ID
    assert ids(f"clave: {token}", "notas.txt") == [rule_id]


def test_words_that_look_like_the_new_prefixes_are_not_tokens():
    for line in ("pul-request-template", "r8_unorm_srgb_block_format_texture", "gsk_renderer_render_texture(renderer)",
                 "lin_api_version = 3", "dp.pt.x", "hvs.io/docs"):  # fmt: skip
        assert ids(line, "notas.txt") == [], line


# Hook


def test_hook_explains_itself_when_leakhound_is_gone(tmp_path):
    import subprocess

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    hook = install_hook(tmp_path)
    script = hook.read_text().replace(__import__("sys").executable, "/no/existe/python3")
    hook.write_text(script)
    result = subprocess.run([str(hook)], capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode != 0
    assert "leakhound hook install" in result.stderr and "--no-verify" in result.stderr

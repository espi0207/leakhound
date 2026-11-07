"""Reglas añadidas en noviembre de 2026.

Los tokens se montan por partes al ejecutar (igual que en fakes.py) para que en el código
no haya ninguno completo: el secret scanning de GitHub podría bloquear el push.
"""

import random
import string

import pytest

from leakhound.scanner import scan_line, scan_text

rng = random.Random(11)
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
B64 = ALNUM + "+/"


def r(n: int, alphabet: str = ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def rules_in(line: str, path: str = "app.py") -> list[str]:
    return [rule.id for rule, _, _ in scan_line(line, path)]


@pytest.mark.parametrize(
    "line, rule",
    [
        (f'HF_TOKEN = "{"hf" + "_" + r(34)}"', "huggingface-token"),
        (f"export DO_TOKEN={'dop' + '_v1_' + r(64, HEX)}", "digitalocean-token"),
        (f"echo {'dckr' + '_pat_' + r(27)} | docker login -u ana --password-stdin", "docker-hub-token"),
        (f"SHOPIFY = '{'shp' + 'at_' + r(32, HEX)}'", "shopify-token"),
        (f"STRIPE_WEBHOOK={'wh' + 'sec_' + r(32)}", "stripe-webhook-secret"),
        (f"mailgun.auth = ('api', '{'ke' + 'y-' + r(32, HEX)}')", "mailgun-api-key"),
        (f"TWILIO_KEY = '{'S' + 'K' + r(32, HEX)}'", "twilio-api-key"),
        (f'"client_secret": "{"GOC" + "SPX-" + r(28)}"', "google-oauth-secret"),
        (f"AccountName=tienda;{'Account' + 'Key='}{r(86, B64)}==;EndpointSuffix=core.windows.net", "azure-storage-key"),
        (f"AZURE_CLIENT_SECRET = '{r(3) + '8' + 'Q~' + r(34)}'", "azure-client-secret"),
        (f"DATABRICKS_TOKEN = '{'da' + 'pi' + r(32, HEX)}'", "databricks-token"),
        (f"NEW_RELIC = '{'NR' + 'AK-' + r(27, string.ascii_uppercase + string.digits)}'", "new-relic-key"),
        (f"GRAFANA = '{'gl' + 'sa_' + r(32) + '_' + r(8, HEX)}'", "grafana-token"),
        (f"POSTMAN = '{'PM' + 'AK-' + r(24, HEX) + '-' + r(34, HEX)}'", "postman-api-key"),
        ("AGE-SECRET-" + "KEY-1" + r(58, "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"), "age-secret-key"),
        (f"runner_token = '{'gl' + 'rt-' + r(20)}'", "gitlab-token"),
        ("SLACK_APP = '" + "xa" + "pp-1-" + r(11, string.ascii_uppercase) + "-" + r(13, string.digits) + "-"
         + r(64, HEX) + "'", "slack-token"),  # fmt: skip
        ("PuTTY-User-" + "Key-File-3: ssh-ed25519", "private-key"),
        (f"admin:{'$2b' + '$12$' + r(53, ALNUM + './')}", "password-hash"),
        (f"root:{'$6' + '$' + r(16, ALNUM + './') + '$' + r(86, ALNUM + './')}:19000:0:99999:7:::", "password-hash"),
        (f'conn = "Server=sql01;Database=ventas;User Id=sa;Password={r(16)};"', "connection-string-password"),
        (f'url = "jdbc:mysql://db01:3306/ventas?user=app&password={r(16)}"', "url-query-password"),
        (f"<dbPassword>{r(20)}</dbPassword>", "xml-secret"),
    ],
)
def test_new_rules_find_their_secret(line, rule):
    assert rules_in(line) == [rule]


@pytest.mark.parametrize(
    "line",
    [
        "Server=sql01;Database=ventas;Integrated Security=true;",
        'conn = "Server=sql01;Database=ventas;User Id=sa;Password={0};"',
        "https://ejemplo.com/reset?password=&token=",
        "<password>${DB_PASSWORD}</password>",
        "<apiKey>changeme</apiKey>",
        "hf_hub_download(repo_id='bert-base-uncased', filename='config.json')",
        "key-value store",
        "SKIP_TESTS = true",
        "$2b$ es el prefijo de bcrypt",
        "en cadenas de conexión (`Server=...;Password=...`), en etiquetas XML",
        "mysql://db/ventas?user=app&password=…",
    ],
)
def test_new_rules_no_false_positives(line):
    assert rules_in(line) == []


@pytest.mark.parametrize("name", [".netrc", "_netrc"])
def test_netrc_password(name):
    assert rules_in(f"machine api.ejemplo.com login ana password {r(18)}", name) == ["netrc-password"]


@pytest.mark.parametrize("name, line", [
    (".npmrc", f"//registry.npmjs.org/:_authToken={r(8, HEX)}-{r(4, HEX)}-{r(4, HEX)}-{r(4, HEX)}-{r(12, HEX)}"),
    (".pypirc", f"password = {r(30)}"),
    ("prod.tfvars", f"db_password = {r(20)}"),
])  # fmt: skip
def test_more_config_files(name, line):
    assert rules_in(line, name) == ["generic-secret-config"]


def pem(body_line: str) -> str:
    header, footer = "-----BEGIN " + "OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"
    return "\n".join([header, body_line, r(70), footer])


def test_two_private_keys_have_different_fingerprints():
    # Antes la huella era solo la cabecera: ignorar una clave ignoraba todas las del mismo tipo.
    [a] = scan_text(pem(r(70)), "a_id")
    [b] = scan_text(pem(r(70)), "b_id")
    assert a.fingerprint != b.fingerprint


def test_the_same_private_key_keeps_its_fingerprint():
    body = r(70)
    [a] = scan_text(pem(body), "id_ed25519")
    [b] = scan_text("# copia\n" + pem(body), "backup/id_ed25519")
    assert a.fingerprint == b.fingerprint and a.line == 1 and b.line == 2
    assert a.masked.startswith("----")  # no enseña el cuerpo

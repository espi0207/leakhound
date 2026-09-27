import pytest

from leakhound.fakes import Fakes
from leakhound.rules import RULES, entropy
from leakhound.scanner import scan_line

fake = Fakes(seed=42)


def rules_in(line: str, path: str = "app.py") -> list[str]:
    return [rule.id for rule, _, _ in scan_line(line, path)]


@pytest.mark.parametrize(
    "line, rule",
    [
        (f'GITHUB_TOKEN = "{fake.github_token()}"', "github-token"),
        (f"aws_access_key_id = {fake.aws_key_id()}", "aws-access-key-id"),
        (f"aws_secret_access_key = {fake.aws_secret()}", "aws-secret-access-key"),
        (f'stripe.api_key = "{fake.stripe_key()}"', "stripe-secret-key"),
        (f"curl -X POST {fake.slack_webhook()}", "slack-webhook"),
        (f"BOT={fake.telegram_token()}", "telegram-bot-token"),
        (f"const KEY = '{fake.google_key()}';", "google-api-key"),
        (fake.private_key().splitlines()[0], "private-key"),
        (f"Authorization: Bearer {fake.jwt()}", "jwt"),
        (f"DATABASE_URL={fake.database_url()}", "url-password"),
        (f'db_password = "{fake.password()}"', "generic-secret"),
    ],
)
def test_each_rule_finds_its_secret(line, rule):
    assert rules_in(line) == [rule]


def test_generic_rule_is_dropped_when_a_specific_one_matches():
    # "token = ..." encaja con la regla genérica, pero ya se sabe que es de GitHub.
    assert rules_in(f'token = "{fake.github_token()}"') == ["github-token"]


@pytest.mark.parametrize(
    "line",
    [
        'password = "changeme123"',
        'password = "hunter2"',  # demasiado corta
        'password = "contraseñadeprueba"',  # palabras normales: entropía baja
        'api_key = "${API_KEY}"',
        "password = os.environ['DB_PASSWORD']",
        "postgres://user:password@localhost:5432/app",
        "redis://:pass@localhost",
        "aws_access_key_id = AKIA" + "IOSFODNN7EXAMPLE",  # la de la documentación de AWS
        "token = 'xxxxxxxxxxxxxxxxxxxx'",
        "Esto es un texto normal con la palabra token y password por medio.",
    ],
)
def test_no_false_positives(line):
    assert rules_in(line) == []


def test_inline_ignore():
    line = f'TOKEN = "{fake.github_token()}"  # leakhound:ignore (token revocado, lo dejo de ejemplo)'
    assert rules_in(line) == []


def test_column_points_at_the_secret():
    token = fake.github_token()
    [(_, col, secret)] = scan_line(f'x = "{token}"')
    assert secret == token and col == 6


def test_entropy():
    assert entropy("") == 0
    assert entropy("aaaaaaaa") == 0
    assert entropy("abcd") == 2
    assert entropy(fake.password()) > 3.5


def test_rule_ids_are_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    "line",
    [
        f'DB_PASSWORD = "{fake.password()}"',
        f'SECRET_KEY = "{fake.password()}"',  # el de Django
        f'const dbPassword = "{fake.password()}";',
        f'{{"client_secret": "{fake.password()}"}}',
    ],
)
def test_generic_rule_understands_real_variable_names(line):
    assert rules_in(line) == ["generic-secret"]


def test_unquoted_values_only_count_in_config_files():
    line = f"DB_PASSWORD={fake.password()}"
    assert rules_in(line, ".env") == ["generic-secret-config"]
    assert rules_in(line, "config/.env.production") == ["generic-secret-config"]
    assert rules_in(f"  password: {fake.password()}  # la de producción", "docker-compose.yml") == [
        "generic-secret-config"
    ]
    # En código, un valor sin comillas es una variable, no un secreto.
    assert rules_in("token = request_headers_token_value", "app.py") == []
    assert rules_in(line, "app.py") == []


@pytest.mark.parametrize(
    "line",
    [
        'password = f"{get_password()}"',
        "url = f'postgres://app:{db_pass}@localhost/app'",
        'token: "{{ secrets.DEPLOY_TOKEN }}"',
        "DB_PASSWORD=${DB_PASSWORD_FROM_VAULT}",
    ],
)
def test_templates_are_not_secrets(line):
    assert rules_in(line, ".env") == [] and rules_in(line, "app.py") == []


@pytest.mark.parametrize(
    "line, path",
    [
        # Casos sacados de dependencias reales de npm, que no son secretos:
        ('lastSignificantToken = "?InterpolationInTemplate";', "index.mjs"),  # un nombre, no un token
        ("password: 'bm90IG15IHJlYWwgcGFzc3dvcmQ=',", "README.md"),  # base64 de "not my real password"
        ("token: 'Zm9vYmFyOmZvb2Jhcg==',", "auth.test.js"),  # base64 de "foobar:foobar"
        ("'socks://your-name%40gmail.com:abcdef12345124@proxy.example.net'", "README.md"),
        ('key="-----BEGIN PRIVATE KEY-----\\nXXXX\\nXXXX\\n-----END PRIVATE KEY-----"', "config.md"),
    ],
)
def test_documentation_and_test_values_are_not_reported(line, path):
    assert rules_in(line, path) == []


def test_real_looking_credentials_in_base64_are_reported():
    import base64

    value = base64.b64encode(b"admin:" + fake.password().encode()).decode()
    assert rules_in(f'auth_token = "{value}"') == ["generic-secret"]

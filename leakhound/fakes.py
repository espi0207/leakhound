"""Secretos falsos con el formato de los de verdad, para la demo y las pruebas.

Se montan por partes al ejecutarse ("gh" + "p_" + ...) para que en el código fuente no
haya ningún token completo. Si lo hubiera, el propio GitHub podría bloquear el push (su
secret scanning no sabe que son de mentira) y leakhound se encontraría a sí mismo.
"""

from __future__ import annotations

import random
import string

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits


class Fakes:
    def __init__(self, seed: int = 1) -> None:
        self.rng = random.Random(seed)

    def _rand(self, n: int, alphabet: str = ALNUM) -> str:
        return "".join(self.rng.choice(alphabet) for _ in range(n))

    def github_token(self) -> str:
        return "gh" + "p_" + self._rand(36)

    def aws_key_id(self) -> str:
        return "AK" + "IA" + self._rand(16, UPPER_DIGITS)

    def aws_secret(self) -> str:
        return self._rand(40, ALNUM + "/+")

    def stripe_key(self) -> str:
        return "sk" + "_live_" + self._rand(24)

    def slack_webhook(self) -> str:
        return (
            "https://hooks." + "slack.com/services/"
            f"T{self._rand(8, UPPER_DIGITS)}/B{self._rand(8, UPPER_DIGITS)}/{self._rand(24)}"
        )

    def telegram_token(self) -> str:
        return f"{self.rng.randint(10**8, 10**9 - 1)}:" + "AA" + self._rand(33)

    def google_key(self) -> str:
        return "AI" + "za" + self._rand(35)

    def private_key(self) -> str:
        body = "\n".join(self._rand(70) for _ in range(3))
        return f"-----BEGIN {'OPENSSH'} PRIVATE KEY-----\n{body}\n-----END {'OPENSSH'} PRIVATE KEY-----"

    def jwt(self) -> str:
        return "ey" + "J" + self._rand(20) + ".ey" + "J" + self._rand(40) + "." + self._rand(43)

    def password(self) -> str:
        return self._rand(18, ALNUM + "!#%&*")

    def database_url(self) -> str:
        return "postgres://app:" + self._rand(16) + "@db.interno:5432/tienda"

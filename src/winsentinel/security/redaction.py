"""Redaction of secrets from command lines.

Command lines routinely contain credentials (``--password=hunter2``, ``curl -H "Authorization:
Bearer …"``, ``https://user:pass@host``). WinSentinel redacts them **at collection time** so a
secret never reaches the event bus, the database, log files or the terminal.

Detection does not lose anything important: rules care that ``-EncodedCommand`` or
``--password`` *appears*, never about the secret's value.

The redaction is conservative by design: it targets unambiguous secret-bearing names and forms.
Short flags such as ``-p`` are *not* redacted because they mean "port" as often as "password".
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

REDACTED: Final = "***REDACTED***"

_SECRET_NAMES: Final = (
    "password",
    "passwd",
    "pwd",
    "pass",
    "passphrase",
    "secret",
    "client-secret",
    "client_secret",
    "token",
    "access-token",
    "access_token",
    "refresh-token",
    "auth-token",
    "api-key",
    "api_key",
    "apikey",
    "access-key",
    "secret-key",
    "private-key",
    "connectionstring",
    "connection-string",
    "sas",
)
_NAME_ALT: Final = "|".join(re.escape(name) for name in _SECRET_NAMES)

# `--password` / `-password` / `/password` as a standalone argument: the *next* argument is secret.
_FLAG_ONLY: Final = re.compile(rf"^(?:--?|/)(?:{_NAME_ALT})$", re.IGNORECASE)
# `--password=value`, `/password:value`, `password=value` inside one argument.
_FLAG_WITH_VALUE: Final = re.compile(
    rf"(?P<prefix>(?:^|[\s;&?])(?:--?|/)?(?:{_NAME_ALT})\s*[=:]\s*)(?P<value>[^\s;&]+)",
    re.IGNORECASE,
)
_BEARER: Final = re.compile(
    r"(?P<prefix>\b(?:Bearer|Basic)\s+)(?P<value>[A-Za-z0-9._~+/=-]+)", re.IGNORECASE
)
_URL_CREDENTIALS: Final = re.compile(
    r"(?P<prefix>[a-z][a-z0-9+.-]*://[^/\s:@]+:)(?P<value>[^@\s/]+)(?=@)", re.IGNORECASE
)


def _redact_inline(argument: str) -> str:
    argument = _FLAG_WITH_VALUE.sub(lambda m: m.group("prefix") + REDACTED, argument)
    argument = _BEARER.sub(lambda m: m.group("prefix") + REDACTED, argument)
    return _URL_CREDENTIALS.sub(lambda m: m.group("prefix") + REDACTED, argument)


def redact_command_line(arguments: Sequence[str]) -> tuple[str, ...]:
    """Return a copy of ``arguments`` with secret values replaced by :data:`REDACTED`."""
    result: list[str] = []
    redact_next = False
    for argument in arguments:
        if redact_next:
            result.append(REDACTED)
            redact_next = False
            continue
        if _FLAG_ONLY.match(argument):
            result.append(argument)
            redact_next = True
            continue
        result.append(_redact_inline(argument))
    return tuple(result)

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_DEFAULT_ADMIN_USER = "lionlock_admin"
_DEFAULT_WRITER_USER = "lionlock_writer"
_DEFAULT_PORT = 25060

# No bare HOST/PORT fallback: platforms set those for the app itself, not for its database.
_ENV_DB_HOST_KEYS = ("LIONLOCK_TELEMETRY_DB_HOST", "LIONLOCK_DB_HOST")
_ENV_DB_PORT_KEYS = ("LIONLOCK_TELEMETRY_DB_PORT", "LIONLOCK_DB_PORT")
_ENV_DB_NAME_KEYS = ("LIONLOCK_TELEMETRY_DB_NAME", "LIONLOCK_DB_NAME")
_ENV_SSLMODE_KEYS_ADMIN = ("LIONLOCK_SSLMODE",)
_ENV_SSLMODE_KEYS_TELEMETRY = ("LIONLOCK_TELEMETRY_SSLMODE", "LIONLOCK_SSLMODE")
_ENV_SSLROOTCERT_KEYS_ADMIN = ("LIONLOCK_SSLROOTCERT",)
_ENV_SSLROOTCERT_KEYS_TELEMETRY = ("LIONLOCK_TELEMETRY_SSLROOTCERT", "LIONLOCK_SSLROOTCERT")

# A .env found implicitly (current directory or repo root) may only supply database connection
# settings. Anything else, such as LIONLOCK_GATING_ENABLED or the upload endpoint, would let a
# file in an untrusted checkout switch gating off or send telemetry elsewhere.
_IMPLICIT_DOTENV_PREFIXES = (
    "LIONLOCK_TELEMETRY_DB_",
    "LIONLOCK_DB_",
    "LIONLOCK_WRITER_",
    "LIONLOCK_ADMIN_",
    "LIONLOCK_SSL",
    "LIONLOCK_TELEMETRY_SSL",
    "LIONLOCK_TELEMETRY_TOKEN",
    "LIONLOCK_SQL_TELEMETRY_TOKEN",
    "LIONLOCK_SQL_TOKEN",
    "LIONLOCK_LOG_TOKEN_",
)


def validate_identifier(name: str, label: str) -> None:
    if not name or not _IDENTIFIER_RE.fullmatch(name):
        raise ValueError(f"Invalid SQL identifier for {label}: {name!r}")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _env_first(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value is None:
            continue
        value = str(value).strip()
        if value:
            return value
    return None


_DOTENV_LOADED: set[tuple[str, int, tuple[str, ...] | None]] = set()


def _read_env_lines(lines: Iterable[str], allowed_prefixes: tuple[str, ...] | None = None) -> None:
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].lstrip()
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        if allowed_prefixes is not None and not key.startswith(allowed_prefixes):
            continue
        value = value.strip()
        if value and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


def load_dotenv(path: str | Path | None = None) -> bool:
    """Load a .env file without overriding variables that are already set.

    An explicit ``path`` is loaded in full. Without one, the first .env in the current directory or
    the repository root is used, and only database connection settings are taken from it.
    """
    candidate: Path | None
    allowed: tuple[str, ...] | None = None
    if path is not None:
        candidate = Path(path)
    else:
        allowed = _IMPLICIT_DOTENV_PREFIXES
        cwd_env = Path.cwd() / ".env"
        root = _repo_root()
        candidates = [
            cwd_env,
            root / ".env",
        ]
        candidate = None
        for item in candidates:
            if item.is_file():
                candidate = item
                break
    if candidate is None or not candidate.is_file():
        return False
    stamp = (str(candidate.resolve()), candidate.stat().st_mtime_ns, allowed)
    if stamp in _DOTENV_LOADED:
        # Loading never overrides a set variable, so re-reading an unchanged file (once per SQL
        # event before) cannot change anything.
        return True
    _read_env_lines(candidate.read_text(encoding="utf-8").splitlines(), allowed)
    _DOTENV_LOADED.add(stamp)
    return True


def _resolve_host_port() -> tuple[str, int]:
    host = _env_first(*_ENV_DB_HOST_KEYS)
    if not host:
        raise ValueError("Database host missing (LIONLOCK_TELEMETRY_DB_HOST or LIONLOCK_DB_HOST).")
    port_raw = _env_first(*_ENV_DB_PORT_KEYS) or str(_DEFAULT_PORT)
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ValueError("Database port must be an integer.") from exc
    return host, port


def _resolve_database_name(database: str | None) -> str:
    env_value = _env_first(*_ENV_DB_NAME_KEYS)
    return env_value or (database or "lionlock_prod")


def _resolve_user_password(role: str) -> tuple[str, str]:
    normalized = role.strip().lower()
    if normalized in {"admin", "lionlock_admin"}:
        user = _env_first("LIONLOCK_ADMIN_USER") or _DEFAULT_ADMIN_USER
        password = _env_first("LIONLOCK_ADMIN_PASSWORD")
        if not password:
            raise ValueError("Missing LIONLOCK_ADMIN_PASSWORD.")
        return user, password
    if normalized in {"writer", "lionlock_writer", "telemetry"}:
        user = _env_first("LIONLOCK_WRITER_USER", "LIONLOCK_TELEMETRY_DB_USER") or _DEFAULT_WRITER_USER
        password = _env_first("LIONLOCK_WRITER_PASSWORD", "LIONLOCK_TELEMETRY_DB_PASSWORD")
        if not password:
            raise ValueError("Missing LIONLOCK_WRITER_PASSWORD or LIONLOCK_TELEMETRY_DB_PASSWORD.")
        return user, password
    raise ValueError("Role must be 'admin' or 'writer'.")


def _discover_sslrootcert(env_keys: tuple[str, ...]) -> str | None:
    env_path = _env_first(*env_keys)
    if env_path:
        candidate = Path(env_path)
        if candidate.is_file():
            return str(candidate)
    return None


def _resolve_ssl_settings(role: str) -> tuple[str, str | None]:
    normalized = role.strip().lower()
    if normalized in {"admin", "lionlock_admin"}:
        sslmode = _env_first(*_ENV_SSLMODE_KEYS_ADMIN)
        sslrootcert = _discover_sslrootcert(_ENV_SSLROOTCERT_KEYS_ADMIN)
    else:
        sslmode = _env_first(*_ENV_SSLMODE_KEYS_TELEMETRY)
        sslrootcert = _discover_sslrootcert(_ENV_SSLROOTCERT_KEYS_TELEMETRY)
    if sslmode:
        normalized = sslmode.strip().lower()
        if normalized == "require":
            return normalized, None
        return normalized, sslrootcert
    sslmode = "verify-ca" if sslrootcert else "require"
    return sslmode, sslrootcert


def build_postgres_dsn(role: str, *, database: str = "lionlock_prod") -> str:
    load_dotenv()
    user, password = _resolve_user_password(role)
    host, port = _resolve_host_port()
    database = _resolve_database_name(database)
    sslmode, sslrootcert = _resolve_ssl_settings(role)
    params: list[tuple[str, str]] = [("sslmode", sslmode)]
    if sslrootcert and sslmode != "require":
        params.append(("sslrootcert", sslrootcert))
    query = urlencode(params)
    safe_user = quote(user, safe="")
    safe_password = quote(password, safe="")
    return f"postgresql://{safe_user}:{safe_password}@{host}:{port}/{database}?{query}"


_REDACTED = "REDACTED"
# A setting is secret when its name contains one of these (password, sslpassword, passfile, ...),
# or when its value mentions a password (``options=-c password=...``). Over-redacting is safe.
_SECRET_NAME_PARTS = ("pass", "pwd", "secret", "token")
# libpq conninfo: ``key = value``, where value is a single-quoted string, or an unquoted run of
# characters ending at whitespace. Both forms take backslash escapes, so "ab\ cd" is one value.
_CONNINFO_PAIR = re.compile(
    r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"('(?:[^'\\]|\\.)*'|(?:[^\s'\\]|\\.)(?:[^\s\\]|\\.)*)\s*"
)
# A URL connection string starts with its scheme. "://" elsewhere (inside a conninfo value, for
# example) does not make a string a URL.
_URL_DSN = re.compile(r"\s*[A-Za-z][A-Za-z0-9+.-]*://")


def _is_secret_setting(key: str, value: str) -> bool:
    name = key.lower()
    return any(part in name for part in _SECRET_NAME_PARTS) or "pass" in value.lower()


def _redact_url_dsn(dsn: str) -> str:
    split = urlsplit(dsn)
    # An unencoded "#" or "?" in a password moves the rest of it into the fragment or query, where
    # it would be shown. A connection string has no fragment, and "@" after the host means the
    # split went wrong, so either makes the whole string unparseable.
    if split.fragment or "@" in split.path or "@" in split.query:
        raise ValueError("unparseable connection string")
    if split.port is not None and not 0 <= split.port <= 65535:
        raise ValueError("port out of range")
    hostport = split.netloc.rpartition("@")[2]
    netloc = ""
    if split.username:
        netloc = quote(split.username, safe="")
        if split.password is not None:
            netloc += ":" + _REDACTED
        netloc += "@"
    elif split.password is not None:
        netloc = ":" + _REDACTED + "@"
    netloc += hostport
    query_pairs = [
        (key, _REDACTED if _is_secret_setting(key, value) else value)
        for key, value in parse_qsl(split.query, keep_blank_values=True)
    ]
    # Built by hand rather than with urlunsplit, which drops the "//" of an empty host
    # ("sqlite:///x.db" would be shown as "sqlite:/x.db").
    query = urlencode(query_pairs)
    return f"{split.scheme}://{netloc}{split.path}" + (f"?{query}" if query else "")


def _conninfo_value(raw: str) -> str:
    """The value libpq sees: quotes removed and backslash escapes decoded ("p\\ass" is "pass")."""
    if raw.startswith("'"):
        raw = raw[1:-1]
    return re.sub(r"\\(.)", r"\1", raw, flags=re.DOTALL)


def _redact_conninfo(dsn: str) -> str:
    parts = []
    position = 0
    while position < len(dsn):
        match = _CONNINFO_PAIR.match(dsn, position)
        if match is None or match.end() == position:
            raise ValueError("unparseable connection string")
        key, value = match.group(1), match.group(2)
        # Classify the decoded value, so escapes cannot split a word such as "password"; a value
        # that is not secret keeps its original spelling.
        secret = _is_secret_setting(key, _conninfo_value(value))
        parts.append(f"{key}={_REDACTED if secret else value}")
        position = match.end()
    return " ".join(parts)


def redact_dsn(dsn: str) -> str:
    """Return ``dsn`` with every password-like setting replaced by ``REDACTED``.

    Handles URL connection strings and libpq ``key=value`` strings. Anything it cannot parse is
    redacted whole, so a malformed string never reaches the output.
    """
    try:
        if _URL_DSN.match(dsn):
            return _redact_url_dsn(dsn)
        return _redact_conninfo(dsn)
    except ValueError:
        return _REDACTED

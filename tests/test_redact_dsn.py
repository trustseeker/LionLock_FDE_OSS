"""``redact_dsn`` must never return a secret, whatever form the connection string takes.

It is a public helper for showing a connection string to a person. A string it cannot parse is
redacted whole rather than shown.
"""

import pytest

from lionlock.logging.connection import redact_dsn

SECRET = "S3cretPW"
HOST = "db.example.com"


@pytest.mark.parametrize(
    "dsn",
    [
        f"postgresql://user:{SECRET}@{HOST}:5432/ll",
        f"postgresql://user@{HOST}/ll?password={SECRET}",
        f"postgresql://user@{HOST}/ll?PASSWORD={SECRET}",
        f"postgresql://user@{HOST}/ll?sslpassword={SECRET}",
        f"postgresql://user@{HOST}/ll?options=-c%20password%3D{SECRET}",
        f"postgresql://user:{SECRET}@{HOST}/ll#{SECRET}",
        f"postgresql://user:{SECRET}@{HOST}:notaport/ll",
        f"mysql+pymysql://user:{SECRET}@{HOST}/ll",
        f"host=db.example.com user=user password={SECRET} dbname=ll",
        f"host=db.example.com user=user PASSWORD={SECRET} dbname=ll",
        f"host=db.example.com user=user password = {SECRET} dbname=ll",
        f"host=db.example.com user=user password='{SECRET} two words' dbname=ll",
        f"host=db.example.com user=user password='it\\'s {SECRET}' dbname=ll",
        f"host=db.example.com sslpassword={SECRET}",
        f"host=db.example.com user=user password='{SECRET}",
        f"postgresql://user:12#{SECRET}@{HOST}/ll",
        f"host=db.example.com user=user password=a://{SECRET} dbname=ll",
        f"host=db.example.com user=user password=abc\\ x={SECRET} dbname=ll",
        f"host=db.example.com user=user password={SECRET}\\",
        f"host=db.example.com options=-c\\ p\\assword={SECRET}",
        f"host=db.example.com options='-c p\\assword={SECRET}'",
        f"postgresql://user:pa?{SECRET}@{HOST}/ll",
    ],
)
def test_no_form_of_connection_string_reveals_the_secret(dsn: str) -> None:
    assert SECRET not in redact_dsn(dsn)


def test_useful_parts_are_kept() -> None:
    assert (
        redact_dsn(f"postgresql://user:{SECRET}@{HOST}:5432/ll?sslmode=require")
        == f"postgresql://user:REDACTED@{HOST}:5432/ll?sslmode=require"
    )
    assert (
        redact_dsn(f"host=db.example.com user=user password = '{SECRET} x' dbname=ll")
        == "host=db.example.com user=user password=REDACTED dbname=ll"
    )


def test_backslash_escaped_space_stays_inside_the_value() -> None:
    # libpq lets an unquoted value contain an escaped space: "ab\\ cd" is one value.
    assert (
        redact_dsn(f"host=db.example.com password=ab\\ {SECRET} dbname=ll")
        == "host=db.example.com password=REDACTED dbname=ll"
    )


def test_a_value_that_is_not_secret_keeps_its_spelling() -> None:
    assert redact_dsn("host=db.example.com application_name=my\\ app") == (
        "host=db.example.com application_name=my\\ app"
    )


def test_a_url_without_a_host_keeps_its_double_slash() -> None:
    assert redact_dsn("sqlite:///tmp/telemetry.db") == "sqlite:///tmp/telemetry.db"


def test_ipv6_host_keeps_its_brackets() -> None:
    assert (
        redact_dsn(f"postgresql://user:{SECRET}@[::1]:5432/ll")
        == "postgresql://user:REDACTED@[::1]:5432/ll"
    )

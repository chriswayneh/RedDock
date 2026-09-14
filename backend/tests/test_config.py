from pathlib import Path

import pytest


def _clear_database_components(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "REDDOCK_DATABASE_HOST",
        "REDDOCK_DATABASE_PORT",
        "REDDOCK_DATABASE_NAME",
        "REDDOCK_DATABASE_USER",
        "REDDOCK_DATABASE_PASSWORD_FILE",
    ):
        monkeypatch.delenv(name, raising=False)


def test_local_deployment_mode_is_default(monkeypatch: pytest.MonkeyPatch):
    from app.config import get_settings

    monkeypatch.delenv("REDDOCK_DEPLOYMENT_MODE", raising=False)
    get_settings.cache_clear()

    assert get_settings().deployment_mode == "local"


def test_sqlite_instance_lock_root_follows_database_not_token(tmp_path: Path):
    from app.config import Settings, local_state_directory

    database = tmp_path / "state" / "reddock.db"
    settings = Settings(
        database_url=f"sqlite:///{database}",
        evidence_dir=str(database.parent / "evidence"),
        operator_token_file=str(tmp_path / "secrets" / "operator-token"),
    )

    assert local_state_directory(settings) == database.parent


def test_public_origin_cannot_silently_widen_local_mode(monkeypatch: pytest.MonkeyPatch):
    from app.config import ConfigurationError, get_settings

    monkeypatch.delenv("REDDOCK_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setenv("REDDOCK_PUBLIC_ORIGIN", "https://red.example")
    get_settings.cache_clear()

    with pytest.raises(ConfigurationError, match="REDDOCK_PUBLIC_ORIGIN"):
        get_settings()


@pytest.mark.parametrize("mode", ["server", "shared", "production", "invalid"])
def test_unimplemented_or_unknown_deployment_modes_fail_closed(
    mode: str, monkeypatch: pytest.MonkeyPatch
):
    from app.config import ConfigurationError, get_settings

    monkeypatch.setenv("REDDOCK_DEPLOYMENT_MODE", mode)
    get_settings.cache_clear()

    with pytest.raises(ConfigurationError, match="REDDOCK_DEPLOYMENT_MODE"):
        get_settings()


def test_database_password_file_builds_a_masked_postgres_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import app.database
    from app.config import get_settings

    secret = tmp_path / "database-password"
    secret.write_text("not-printed:with-special@characters\n", encoding="utf-8")
    monkeypatch.setenv("REDDOCK_DATABASE_HOST", "postgres")
    monkeypatch.setenv("REDDOCK_DATABASE_PORT", "5432")
    monkeypatch.setenv("REDDOCK_DATABASE_NAME", "reddock")
    monkeypatch.setenv("REDDOCK_DATABASE_USER", "reddock")
    monkeypatch.setenv("REDDOCK_DATABASE_PASSWORD_FILE", str(secret))
    get_settings.cache_clear()
    app.database.configure_engine()

    settings = get_settings()
    assert settings.database_password is not None
    assert "not-printed" not in repr(settings)
    assert app.database.engine.url.drivername == "postgresql+psycopg"
    assert app.database.engine.url.host == "postgres"
    assert app.database.engine.url.render_as_string(hide_password=True).endswith(
        "@postgres:5432/reddock"
    )
    assert "not-printed" not in str(app.database.engine.url)


def test_provider_key_file_is_masked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from app.config import get_settings

    secret = tmp_path / "provider-key"
    secret.write_text("provider-secret\n", encoding="utf-8")
    monkeypatch.delenv("REDDOCK_LLM_API_KEY", raising=False)
    monkeypatch.setenv("REDDOCK_LLM_API_KEY_FILE", str(secret))
    get_settings.cache_clear()

    settings = get_settings()
    assert settings.llm_api_key is not None
    assert settings.llm_api_key.get_secret_value() == "provider-secret"
    assert "provider-secret" not in repr(settings)


def test_incomplete_database_components_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from app.config import ConfigurationError, get_settings

    _clear_database_components(monkeypatch)
    secret = tmp_path / "database-password"
    secret.write_text("only-a-password", encoding="utf-8")
    monkeypatch.setenv("REDDOCK_DATABASE_PASSWORD_FILE", str(secret))
    get_settings.cache_clear()

    with pytest.raises(ConfigurationError, match="requires"):
        get_settings()


def test_direct_database_url_is_not_rendered_in_settings(
    monkeypatch: pytest.MonkeyPatch,
):
    from app.config import get_settings

    _clear_database_components(monkeypatch)
    monkeypatch.setenv(
        "REDDOCK_DATABASE_URL",
        "postgresql+psycopg://reddock:must-not-render@database.example/reddock",
    )
    get_settings.cache_clear()

    assert "must-not-render" not in repr(get_settings())


def test_secret_files_reject_symlinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from app.config import ConfigurationError, get_settings

    target = tmp_path / "provider-key"
    target.write_text("secret", encoding="utf-8")
    link = tmp_path / "provider-key-link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("This platform does not permit an unprivileged test symlink")
    monkeypatch.setenv("REDDOCK_LLM_API_KEY_FILE", str(link))
    get_settings.cache_clear()

    with pytest.raises(ConfigurationError, match="non-symlink"):
        get_settings()


def test_provider_key_file_and_direct_value_are_mutually_exclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from app.config import ConfigurationError, get_settings

    secret = tmp_path / "provider-key"
    secret.write_text("file-secret", encoding="utf-8")
    monkeypatch.setenv("REDDOCK_LLM_API_KEY", "environment-secret")
    monkeypatch.setenv("REDDOCK_LLM_API_KEY_FILE", str(secret))
    get_settings.cache_clear()

    with pytest.raises(ConfigurationError, match="only one"):
        get_settings()


def _dormant_server_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    client_secret = tmp_path / "oidc-client-secret"
    client_secret.write_text("confidential-client-secret", encoding="utf-8")
    database_secret = tmp_path / "database-secret"
    database_secret.write_text("database-secret", encoding="utf-8")
    rate_limit_key = tmp_path / "rate-limit-key"
    rate_limit_key.write_text("ab" * 32 + "\n", encoding="utf-8")
    limiter_database_secret = tmp_path / "limiter-database-secret"
    limiter_database_secret.write_text("independent-limiter-secret", encoding="utf-8")
    values = {
        "REDDOCK_PUBLIC_ORIGIN": "https://reddock.example",
        "REDDOCK_OIDC_ISSUER": "https://identity.example/realms/reddock",
        "REDDOCK_OIDC_CLIENT_ID": "reddock",
        "REDDOCK_OIDC_CLIENT_SECRET_FILE": str(client_secret),
        "REDDOCK_OIDC_ENDPOINT_ORIGINS": "https://identity.example,https://keys.example",
        "REDDOCK_SERVER_ORGANIZATION_SLUG": "example-team",
        "REDDOCK_TRUSTED_PROXY_CIDRS": "10.20.0.2,2001:db8:20::2/128",
        "REDDOCK_DATABASE_HOST": "postgres",
        "REDDOCK_DATABASE_PORT": "5432",
        "REDDOCK_DATABASE_NAME": "reddock",
        "REDDOCK_DATABASE_USER": "reddock",
        "REDDOCK_DATABASE_PASSWORD_FILE": str(database_secret),
        "REDDOCK_RATE_LIMIT_KEY_FILE": str(rate_limit_key),
        "REDDOCK_RATE_LIMIT_DATABASE_USER": "reddock_limiter",
        "REDDOCK_RATE_LIMIT_DATABASE_PASSWORD_FILE": str(limiter_database_secret),
        "REDDOCK_SERVER_WORKERS": "1",
    }
    monkeypatch.delenv("REDDOCK_DATABASE_URL", raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return values


def test_dormant_server_identity_contract_parses_without_enabling_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from app.config import (
        ConfigurationError,
        dormant_server_identity_config,
        dormant_server_runtime_config,
        get_settings,
    )

    _dormant_server_environment(tmp_path, monkeypatch)
    parsed = dormant_server_identity_config()

    assert parsed.public_origin == "https://reddock.example"
    assert parsed.oidc_issuer == "https://identity.example/realms/reddock"
    assert parsed.oidc_endpoint_origins == (
        "https://identity.example",
        "https://keys.example",
    )
    assert parsed.trusted_proxy_cidrs == ("10.20.0.2/32", "2001:db8:20::2/128")
    assert "confidential-client-secret" not in repr(parsed)
    runtime = dormant_server_runtime_config()
    assert runtime.rate_limit_key.get_secret_value() == bytes.fromhex("ab" * 32)
    assert runtime.rate_limit_database_user == "reddock_limiter"
    assert (
        runtime.rate_limit_database_password.get_secret_value()
        == "independent-limiter-secret"
    )
    assert "abababab" not in repr(runtime)
    assert "independent-limiter-secret" not in repr(runtime)

    monkeypatch.setenv("REDDOCK_DEPLOYMENT_MODE", "server")
    get_settings.cache_clear()
    with pytest.raises(ConfigurationError, match="not available"):
        get_settings()


@pytest.mark.parametrize(
    "payload",
    [
        "ab" * 31,
        "ab" * 33,
        "AB" * 32,
        "g0" * 32,
        "ab" * 32 + "\nextra",
        "ab" * 31 + "\x00f0",
        "",
    ],
)
def test_dormant_server_runtime_rejects_malformed_limiter_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
):
    from app.config import ConfigurationError, dormant_server_runtime_config

    values = _dormant_server_environment(tmp_path, monkeypatch)
    key_file = Path(values["REDDOCK_RATE_LIMIT_KEY_FILE"])
    key_file.write_text(payload, encoding="utf-8")

    with pytest.raises(ConfigurationError, match="REDDOCK_RATE_LIMIT_KEY_FILE") as rejected:
        dormant_server_runtime_config()
    if payload:
        assert payload not in str(rejected.value)


def test_dormant_server_runtime_requires_a_mounted_limiter_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from app.config import ConfigurationError, dormant_server_runtime_config

    _dormant_server_environment(tmp_path, monkeypatch)
    monkeypatch.delenv("REDDOCK_RATE_LIMIT_KEY_FILE")

    with pytest.raises(ConfigurationError, match="REDDOCK_RATE_LIMIT_KEY_FILE is required"):
        dormant_server_runtime_config()


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("REDDOCK_RATE_LIMIT_DATABASE_USER", None, "requires"),
        ("REDDOCK_RATE_LIMIT_DATABASE_PASSWORD_FILE", None, "requires"),
        ("REDDOCK_RATE_LIMIT_DATABASE_USER", "reddock", "must differ"),
        ("REDDOCK_RATE_LIMIT_DATABASE_USER", "invalid user", "is invalid"),
    ],
)
def test_dormant_server_runtime_requires_a_distinct_limiter_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str | None,
    message: str,
):
    from app.config import ConfigurationError, dormant_server_runtime_config

    _dormant_server_environment(tmp_path, monkeypatch)
    if value is None:
        monkeypatch.delenv(name)
    else:
        monkeypatch.setenv(name, value)

    with pytest.raises(ConfigurationError, match=message):
        dormant_server_runtime_config()


def test_dormant_server_runtime_rejects_reused_database_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from app.config import ConfigurationError, dormant_server_runtime_config

    values = _dormant_server_environment(tmp_path, monkeypatch)
    Path(values["REDDOCK_RATE_LIMIT_DATABASE_PASSWORD_FILE"]).write_text(
        "database-secret", encoding="utf-8"
    )

    with pytest.raises(ConfigurationError, match="independent credential") as error:
        dormant_server_runtime_config()
    assert "database-secret" not in str(error.value)


@pytest.mark.parametrize("workers", ["", "0", "65", "one", "1.5"])
def test_dormant_server_runtime_rejects_invalid_worker_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workers: str,
):
    from app.config import ConfigurationError, dormant_server_runtime_config

    _dormant_server_environment(tmp_path, monkeypatch)
    monkeypatch.setenv("REDDOCK_SERVER_WORKERS", workers)

    with pytest.raises(ConfigurationError, match="REDDOCK_SERVER_WORKERS"):
        dormant_server_runtime_config()


def test_dormant_server_identity_preserves_a_canonical_trailing_slash_issuer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from app.config import dormant_server_identity_config

    _dormant_server_environment(tmp_path, monkeypatch)
    monkeypatch.setenv("REDDOCK_OIDC_ISSUER", "https://identity.example/tenant/")

    assert dormant_server_identity_config().oidc_issuer == "https://identity.example/tenant/"


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("REDDOCK_PUBLIC_ORIGIN", "http://reddock.example", "HTTPS"),
        ("REDDOCK_PUBLIC_ORIGIN", "https://reddock.example/", "without a path"),
        ("REDDOCK_OIDC_ISSUER", "https://IDENTITY.example", "canonical"),
        ("REDDOCK_OIDC_ISSUER", "https://identity.example/a/../b", "issuer path"),
        ("REDDOCK_OIDC_ISSUER", "https://0x7f000001/tenant", "invalid host"),
        ("REDDOCK_OIDC_ISSUER", "https://identity.example./tenant", "DNS host"),
        ("REDDOCK_OIDC_ENDPOINT_ORIGINS", "https://identity.example,http://keys.example", "HTTPS"),
        ("REDDOCK_OIDC_ENDPOINT_ORIGINS", "https://keys.example", "issuer origin"),
        ("REDDOCK_SERVER_ORGANIZATION_SLUG", "local", "non-reserved"),
        ("REDDOCK_TRUSTED_PROXY_CIDRS", "0.0.0.0/0", "at most 65536"),
        ("REDDOCK_TRUSTED_PROXY_CIDRS", "10.20.0.2,10.20.0.2/32", "duplicates"),
        ("REDDOCK_TRUSTED_PROXY_CIDRS", "proxy.internal", "invalid address"),
    ],
)
def test_dormant_server_identity_rejects_unsafe_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
    message: str,
):
    from app.config import ConfigurationError, dormant_server_identity_config

    _dormant_server_environment(tmp_path, monkeypatch)
    monkeypatch.setenv(name, value)

    with pytest.raises(ConfigurationError, match=message):
        dormant_server_identity_config()


def test_dormant_server_identity_is_all_or_none_and_requires_postgres_secret_components(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from app.config import ConfigurationError, dormant_server_identity_config

    values = _dormant_server_environment(tmp_path, monkeypatch)
    monkeypatch.delenv("REDDOCK_OIDC_CLIENT_ID")
    with pytest.raises(ConfigurationError, match="REDDOCK_OIDC_CLIENT_ID"):
        dormant_server_identity_config()

    monkeypatch.setenv("REDDOCK_OIDC_CLIENT_ID", values["REDDOCK_OIDC_CLIENT_ID"])
    monkeypatch.setenv("REDDOCK_DATABASE_URL", "postgresql://embedded-secret@example/reddock")
    with pytest.raises(ConfigurationError, match="forbids REDDOCK_DATABASE_URL"):
        dormant_server_identity_config()


def test_local_mode_rejects_every_dormant_server_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from app.config import ConfigurationError, get_settings

    values = _dormant_server_environment(tmp_path, monkeypatch)
    monkeypatch.delenv("REDDOCK_DEPLOYMENT_MODE", raising=False)
    for name in values:
        if name.startswith("REDDOCK_DATABASE_"):
            continue
        for configured_name in values:
            if configured_name.startswith("REDDOCK_DATABASE_"):
                continue
            monkeypatch.delenv(configured_name, raising=False)
        monkeypatch.setenv(name, values[name])
        get_settings.cache_clear()
        with pytest.raises(ConfigurationError, match="not-yet-available"):
            get_settings()

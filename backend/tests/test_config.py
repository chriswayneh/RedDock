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


def _dormant_server_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, str]:
    client_secret = tmp_path / "oidc-client-secret"
    client_secret.write_text("confidential-client-secret", encoding="utf-8")
    database_secret = tmp_path / "database-secret"
    database_secret.write_text("database-secret", encoding="utf-8")
    values = {
        "REDDOCK_PUBLIC_ORIGIN": "https://reddock.example",
        "REDDOCK_OIDC_ISSUER": "https://identity.example/realms/reddock",
        "REDDOCK_OIDC_CLIENT_ID": "reddock",
        "REDDOCK_OIDC_CLIENT_SECRET_FILE": str(client_secret),
        "REDDOCK_OIDC_ENDPOINT_ORIGINS": "https://identity.example,https://keys.example",
        "REDDOCK_SERVER_ORGANIZATION_SLUG": "example-team",
        "REDDOCK_DATABASE_HOST": "postgres",
        "REDDOCK_DATABASE_PORT": "5432",
        "REDDOCK_DATABASE_NAME": "reddock",
        "REDDOCK_DATABASE_USER": "reddock",
        "REDDOCK_DATABASE_PASSWORD_FILE": str(database_secret),
    }
    monkeypatch.delenv("REDDOCK_DATABASE_URL", raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return values


def test_dormant_server_identity_contract_parses_without_enabling_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from app.config import ConfigurationError, dormant_server_identity_config, get_settings

    _dormant_server_environment(tmp_path, monkeypatch)
    parsed = dormant_server_identity_config()

    assert parsed.public_origin == "https://reddock.example"
    assert parsed.oidc_issuer == "https://identity.example/realms/reddock"
    assert parsed.oidc_endpoint_origins == (
        "https://identity.example",
        "https://keys.example",
    )
    assert "confidential-client-secret" not in repr(parsed)

    monkeypatch.setenv("REDDOCK_DEPLOYMENT_MODE", "server")
    get_settings.cache_clear()
    with pytest.raises(ConfigurationError, match="not available"):
        get_settings()


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

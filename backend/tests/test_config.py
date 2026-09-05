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

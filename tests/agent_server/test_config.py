import json

import pytest
from pydantic import ValidationError

from openhands.agent_server.config import (
    CONFIG_PATH_ENV,
    DEFAULT_CONVERSATION_IDLE_TTL_SECONDS,
    Config,
    load_config,
)


def test_load_config_reads_registered_marketplaces_from_env(monkeypatch, tmp_path):
    config_path = tmp_path / "missing.json"
    monkeypatch.setenv(CONFIG_PATH_ENV, str(config_path))
    monkeypatch.setenv(
        "OH_REGISTERED_MARKETPLACES",
        json.dumps(
            [
                {
                    "name": "team",
                    "source": "https://github.com/org/marketplace",
                    "ref": "main",
                    "repo_path": "marketplace",
                    "auto_load": True,
                }
            ]
        ),
    )

    config = load_config()

    assert len(config.registered_marketplaces) == 1
    registration = config.registered_marketplaces[0]
    assert registration.name == "team"
    assert registration.source == "https://github.com/org/marketplace"
    assert registration.ref == "main"
    assert registration.repo_path == "marketplace"
    assert registration.auto_load is True


def test_load_config_reads_telemetry_deployment_kind_from_env(monkeypatch, tmp_path):
    config_path = tmp_path / "missing.json"
    monkeypatch.setenv(CONFIG_PATH_ENV, str(config_path))
    monkeypatch.setenv("OH_TELEMETRY_DEPLOYMENT_KIND", "remote")

    assert load_config().telemetry.deployment_kind == "remote"


def test_conversation_idle_ttl_defaults_to_twenty_minutes():
    assert DEFAULT_CONVERSATION_IDLE_TTL_SECONDS == 1200.0
    assert Config().conversation_idle_ttl_seconds == 1200.0


def test_conversation_idle_ttl_can_be_disabled_and_overridden(monkeypatch, tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"conversation_idle_ttl_seconds": None}))
    monkeypatch.setenv(CONFIG_PATH_ENV, str(config_path))

    assert load_config().conversation_idle_ttl_seconds is None

    monkeypatch.setenv("OH_CONVERSATION_IDLE_TTL_SECONDS", "300")
    assert load_config().conversation_idle_ttl_seconds == 300.0


def test_conversation_idle_ttl_rejects_non_positive_values():
    with pytest.raises(ValidationError):
        Config(conversation_idle_ttl_seconds=0)


TEAM_MODE_ENV = {
    "OH_GOVERNANCE_DEPLOYMENT_MODE": "team",
    "OH_GOVERNANCE_BRIDGE_TOKEN": "bridge-token",
    "OH_GOVERNANCE_CENTRAL_API_BASE_URL": "http://127.0.0.1:18002",
    "OH_GOVERNANCE_CENTRAL_API_TOKEN_URL": "http://localhost:8080/token",
    "OH_GOVERNANCE_CLIENT_ID": "client-id",
    "OH_GOVERNANCE_CLIENT_SECRET": "client-secret",
}


def _clear_governance_env(monkeypatch, tmp_path):
    monkeypatch.setenv(CONFIG_PATH_ENV, str(tmp_path / "missing.json"))
    for name in list(TEAM_MODE_ENV) + ["OH_GOVERNANCE_ORIGIN_DEVICE_ID"]:
        monkeypatch.delenv(name, raising=False)


def test_load_config_team_mode_with_all_settings_starts(monkeypatch, tmp_path):
    _clear_governance_env(monkeypatch, tmp_path)
    for name, value in TEAM_MODE_ENV.items():
        monkeypatch.setenv(name, value)

    config = load_config()

    assert config.governance_deployment_mode == "team"
    assert config.governance_client_id == "client-id"


@pytest.mark.parametrize(
    "missing_env",
    [name for name in TEAM_MODE_ENV if name != "OH_GOVERNANCE_DEPLOYMENT_MODE"],
)
def test_load_config_team_mode_missing_setting_refuses_to_start(
    monkeypatch, tmp_path, missing_env
):
    # Why this matters: with a connection field unset the server used to start
    # and only log an error per action, leaving actions hanging in
    # WAITING_FOR_CONFIRMATION with no explanation in the GUI.
    _clear_governance_env(monkeypatch, tmp_path)
    for name, value in TEAM_MODE_ENV.items():
        if name != missing_env:
            monkeypatch.setenv(name, value)

    with pytest.raises(ValueError) as exc:
        load_config()

    # The message must name the exact variable the operator has to set.
    assert missing_env in str(exc.value)


def test_load_config_team_mode_error_names_are_the_real_env_names(
    monkeypatch, tmp_path
):
    # Set nothing but the mode, take the variable names straight from the
    # error message, set those, and the config must then load: proves the
    # names in the message are the ones the parser actually reads.
    _clear_governance_env(monkeypatch, tmp_path)
    monkeypatch.setenv("OH_GOVERNANCE_DEPLOYMENT_MODE", "team")
    with pytest.raises(ValueError) as exc:
        load_config()
    named = [
        token.strip(" ,.")
        for token in str(exc.value).split()
        if token.strip(" ,.").startswith("OH_GOVERNANCE_")
    ]
    assert len(named) == 5
    for name in named:
        monkeypatch.setenv(name, "http://x" if name.endswith("_URL") else "x")

    assert load_config().governance_deployment_mode == "team"


def test_load_config_personal_mode_needs_no_governance_settings(monkeypatch, tmp_path):
    _clear_governance_env(monkeypatch, tmp_path)

    assert load_config().governance_deployment_mode == "personal"


def test_directly_built_team_config_stays_permissive():
    # The fail-closed REST tests build partial team configs on purpose;
    # validation belongs to the startup path (load_config) only.
    Config(governance_deployment_mode="team")

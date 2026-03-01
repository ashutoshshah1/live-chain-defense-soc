from fastapi.testclient import TestClient

from live_chain_defense.app import create_app
from live_chain_defense.config import Settings


def _client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def test_production_requires_auth_for_protected_endpoints() -> None:
    client = _client(
        Settings(
            environment="production",
            auth_required=True,
            api_keys=("secret-key",),
            trusted_hosts=("testserver",),
        )
    )

    assert client.get("/health").status_code == 200
    assert client.get("/alerts").status_code == 401


def test_valid_api_key_grants_access() -> None:
    client = _client(
        Settings(
            environment="production",
            auth_required=True,
            api_keys=("secret-key",),
            trusted_hosts=("testserver",),
        )
    )

    response = client.get("/alerts", headers={"x-api-key": "secret-key"})
    assert response.status_code == 200


def test_rate_limit_is_enforced() -> None:
    client = _client(
        Settings(
            environment="production",
            auth_required=True,
            api_keys=("secret-key",),
            rate_limit_per_minute=2,
            trusted_hosts=("testserver",),
        )
    )

    headers = {"x-api-key": "secret-key"}
    assert client.get("/alerts", headers=headers).status_code == 200
    assert client.get("/alerts", headers=headers).status_code == 200
    assert client.get("/alerts", headers=headers).status_code == 429


def test_simulation_path_is_sandboxed() -> None:
    client = _client(
        Settings(
            auth_required=True,
            api_keys=("secret-key",),
            allow_local_file_simulation=False,
            enable_simulation_endpoints=True,
            trusted_hosts=("testserver",),
        )
    )

    response = client.post(
        "/simulate/run",
        headers={"x-api-key": "secret-key"},
        json={"source": "jsonl", "path": "../../../../etc/passwd"},
    )
    assert response.status_code == 400


def test_simulation_endpoint_can_be_disabled() -> None:
    client = _client(
        Settings(
            auth_required=True,
            api_keys=("secret-key",),
            enable_simulation_endpoints=False,
            trusted_hosts=("testserver",),
        )
    )

    response = client.post("/simulate/run", headers={"x-api-key": "secret-key"})
    assert response.status_code == 403


def test_dashboard_shell_and_static_assets_are_available() -> None:
    client = _client(
        Settings(
            environment="production",
            auth_required=True,
            api_keys=("secret-key",),
            trusted_hosts=("testserver",),
        )
    )

    home = client.get("/")
    css = client.get("/web/styles.css")

    assert home.status_code == 200
    assert css.status_code == 200

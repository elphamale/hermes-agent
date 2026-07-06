"""Regression tests: a password-only dashboard-auth provider (supports_password=True,
supports_session=True, no working start_login) must never be routed through the
OAuth redirect-initiation flow.

Before this fix, being the sole registered session provider meant:
  - `_auto_sso_response` (middleware.py) auto-redirected every unauthenticated
    document load to `/auth/login?provider=<name>`
  - that route unconditionally called `provider.start_login(...)`, which such
    a provider raises NotImplementedError from by design (see base.py's own
    docstring: "a pure-password provider... may implement them as stubs that
    raise NotImplementedError")
  - nothing caught NotImplementedError (only ProviderError), so every such
    load surfaced a raw 500 instead of the password-login page.

BasicAuthProvider is the real-world instance of this shape; this test uses a
minimal standalone stub so the fix is verified against the general contract,
not just one concrete plugin.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.dashboard_auth import clear_providers, register_provider
from hermes_cli.dashboard_auth.base import DashboardAuthProvider, LoginStart, Session
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider


class StubPasswordOnlyProvider(DashboardAuthProvider):
    """Minimal password-only provider: supports_password=True, real session
    support, but NO working OAuth redirect -- exactly BasicAuthProvider's
    shape, without depending on that plugin module."""

    name = "stub-password"
    display_name = "Stub Password-Only Provider (test only)"
    supports_password = True

    def start_login(self, *, redirect_uri: str) -> LoginStart:
        raise NotImplementedError(
            "StubPasswordOnlyProvider is password-only; there is no OAuth "
            "redirect flow."
        )

    def complete_login(self, *, code, state, code_verifier, redirect_uri):
        raise NotImplementedError("password-only provider")

    def verify_session(self, *, access_token: str):
        return None

    def refresh_session(self, *, refresh_token: str) -> Session:
        raise NotImplementedError("password-only provider")

    def revoke_session(self, *, refresh_token: str) -> None:
        return None


@pytest.fixture
def password_only_app():
    clear_providers()
    register_provider(StubPasswordOnlyProvider())
    prev_required = getattr(web_server.app.state, "auth_required", None)
    web_server.app.state.auth_required = True
    client = TestClient(web_server.app, base_url="https://fly-app.fly.dev")
    yield client
    clear_providers()
    web_server.app.state.auth_required = prev_required


@pytest.fixture
def oauth_only_app():
    """Control group: a real OAuth-capable provider, to prove the auto-SSO
    redirect still fires normally and this fix doesn't regress it."""
    clear_providers()
    register_provider(StubAuthProvider())
    prev_required = getattr(web_server.app.state, "auth_required", None)
    web_server.app.state.auth_required = True
    client = TestClient(web_server.app, base_url="https://fly-app.fly.dev")
    yield client
    clear_providers()
    web_server.app.state.auth_required = prev_required


def test_auto_sso_does_not_redirect_for_password_only_provider(password_only_app):
    """The root-cause fix: an unauthenticated document load must NOT be
    auto-redirected to /auth/login?provider=<password-only> at all --
    that's the request shape that used to reach start_login() and crash.
    """
    resp = password_only_app.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "provider=" not in resp.headers["location"]


def test_auto_sso_still_redirects_for_oauth_provider(oauth_only_app):
    """Control: the auto-SSO convenience redirect is unaffected for a
    provider that actually implements start_login."""
    resp = oauth_only_app.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "provider=stub" in resp.headers["location"]


def test_root_document_load_renders_login_page_not_500(password_only_app):
    """End-to-end: an unauthenticated document load with only a
    password-only provider registered must render the ordinary /login page
    (password form), never a raw 500."""
    resp = password_only_app.get("/", follow_redirects=True)
    assert resp.status_code == 200
    assert "password" in resp.text.lower()


def test_explicit_auth_login_url_for_password_only_provider_is_400_not_500(
    password_only_app,
):
    """Defense-in-depth: even a stale bookmark / hand-built URL naming the
    password-only provider explicitly gets a clean 400, never a raw 500."""
    resp = password_only_app.get(
        "/auth/login", params={"provider": "stub-password"}
    )
    assert resp.status_code == 400
    assert "password-login" in resp.json()["detail"]


def test_explicit_auth_login_url_still_works_for_oauth_provider(oauth_only_app):
    """Control: the defense-in-depth check doesn't block real OAuth
    providers from their normal redirect-initiation flow."""
    resp = oauth_only_app.get(
        "/auth/login", params={"provider": "stub"}, follow_redirects=False
    )
    assert resp.status_code == 302
    assert "code=stub_code" in resp.headers["location"]

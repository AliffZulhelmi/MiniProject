# ruff: noqa: S101, S105

from __future__ import annotations

import hashlib

import pytest

from mini_wids.ui import auth

TEST_PASSWORD = "correct test password"
TEST_SALT_HEX = b"mini-wids-test-salt".hex()
TEST_ITERATIONS = 1
TEST_HASH_HEX = hashlib.pbkdf2_hmac(
    "sha256",
    TEST_PASSWORD.encode("utf-8"),
    bytes.fromhex(TEST_SALT_HEX),
    TEST_ITERATIONS,
).hex()


@pytest.fixture
def test_credentials(monkeypatch):
    monkeypatch.setattr(auth, "ADMIN_PASSWORD_SALT_HEX", TEST_SALT_HEX)
    monkeypatch.setattr(auth, "ADMIN_PASSWORD_HASH_HEX", TEST_HASH_HEX)
    monkeypatch.setattr(auth, "PASSWORD_HASH_ITERATIONS", TEST_ITERATIONS)


def test_validate_login_input_trims_username_and_password():
    result = auth.validate_login_input(" administrator ", " secret ")

    assert result.ok is True
    assert result.username == "administrator"
    assert result.password == "secret"


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("", "secret"),
        ("administrator", ""),
        ("a" * 65, "secret"),
        ("administrator", "x" * 257),
        ("\x00administrator", "secret"),
        ("administrator", "\x00secret"),
    ],
)
def test_validate_login_input_rejects_empty_oversized_or_control_values(
    username, password
):
    result = auth.validate_login_input(username, password)

    assert result.ok is False
    assert result.public_message == auth.GENERIC_LOGIN_ERROR


def test_verify_credentials_accepts_only_administrator_password(test_credentials):
    assert auth.verify_credentials("administrator", TEST_PASSWORD) is True
    assert auth.verify_credentials("administrator", "wrong") is False
    assert auth.verify_credentials("someone_else", TEST_PASSWORD) is False


def test_rate_limit_blocks_rapid_failed_retry():
    state = {}

    first = auth.record_failed_login(state, now=100.0)
    second = auth.check_login_allowed(state, now=100.1)

    assert first.public_message == auth.GENERIC_LOGIN_ERROR
    assert second.allowed is False
    assert second.public_message == auth.GENERIC_LOGIN_ERROR


def test_failed_attempts_trigger_temporary_lockout():
    state = {}

    for offset in range(auth.MAX_FAILED_ATTEMPTS):
        auth.record_failed_login(
            state,
            now=100.0 + (offset * auth.FAILED_ATTEMPT_DELAY_SECONDS),
        )

    locked = auth.check_login_allowed(state, now=110.0)
    unlocked = auth.check_login_allowed(
        state,
        now=110.0 + auth.LOCKOUT_SECONDS + 1,
    )

    assert locked.allowed is False
    assert locked.public_message == auth.GENERIC_LOGIN_ERROR
    assert unlocked.allowed is True
    assert state[auth.FAILED_ATTEMPTS_KEY] == 0


def test_session_idle_timeout_clears_auth_state():
    state = {}
    auth.mark_authenticated(state, now=100.0)

    authenticated = auth.is_authenticated(
        state,
        now=100.0 + auth.IDLE_TIMEOUT_SECONDS + 1,
    )

    assert authenticated is False
    assert state.get(auth.AUTHENTICATED_KEY) is False
    assert auth.SESSION_ID_KEY not in state


def test_session_absolute_timeout_clears_auth_state():
    state = {}
    auth.mark_authenticated(state, now=100.0)

    authenticated = auth.is_authenticated(
        state,
        now=100.0 + auth.ABSOLUTE_TIMEOUT_SECONDS + 1,
    )

    assert authenticated is False
    assert state.get(auth.AUTHENTICATED_KEY) is False
    assert auth.SESSION_ID_KEY not in state


def test_authenticated_activity_refreshes_idle_deadline_only():
    state = {}
    auth.mark_authenticated(state, now=100.0)

    first_check = auth.is_authenticated(
        state,
        now=100.0 + auth.IDLE_TIMEOUT_SECONDS - 1,
    )
    second_check = auth.is_authenticated(
        state,
        now=100.0 + auth.IDLE_TIMEOUT_SECONDS + 1,
    )

    assert first_check is True
    assert second_check is True
    assert state[auth.LAST_ACTIVITY_AT_KEY] == 100.0 + auth.IDLE_TIMEOUT_SECONDS + 1


def test_logout_clears_authentication_state():
    state = {}
    auth.mark_authenticated(state, now=100.0)

    auth.logout(state)

    assert state.get(auth.AUTHENTICATED_KEY) is False
    assert auth.SESSION_ID_KEY not in state
    assert auth.LOGIN_AT_KEY not in state
    assert auth.LAST_ACTIVITY_AT_KEY not in state


def test_successful_login_resets_failed_attempts_and_sets_session(test_credentials):
    state = {
        auth.FAILED_ATTEMPTS_KEY: 2,
        auth.LAST_FAILED_AT_KEY: 99.0,
    }

    result = auth.authenticate_login(
        state,
        " administrator ",
        f" {TEST_PASSWORD} ",
        now=100.0,
    )

    assert result.authenticated is True
    assert result.public_message == ""
    assert state[auth.AUTHENTICATED_KEY] is True
    assert auth.SESSION_ID_KEY in state
    assert state[auth.FAILED_ATTEMPTS_KEY] == 0
    assert auth.LAST_FAILED_AT_KEY not in state


def test_failed_username_and_password_share_generic_public_result(test_credentials):
    wrong_username_state = {}
    wrong_password_state = {}

    wrong_username = auth.authenticate_login(
        wrong_username_state,
        "someone_else",
        TEST_PASSWORD,
        now=100.0,
    )
    wrong_password = auth.authenticate_login(
        wrong_password_state,
        "administrator",
        "wrong",
        now=100.0,
    )

    assert wrong_username.authenticated is False
    assert wrong_password.authenticated is False
    assert wrong_username.public_message == auth.GENERIC_LOGIN_ERROR
    assert wrong_password.public_message == auth.GENERIC_LOGIN_ERROR
    assert wrong_username_state[auth.FAILED_ATTEMPTS_KEY] == 1
    assert wrong_password_state[auth.FAILED_ATTEMPTS_KEY] == 1


def test_lockout_blocks_valid_credential_until_expired(test_credentials):
    state = {}
    for offset in range(auth.MAX_FAILED_ATTEMPTS):
        auth.record_failed_login(
            state,
            now=100.0 + (offset * auth.FAILED_ATTEMPT_DELAY_SECONDS),
        )

    blocked = auth.authenticate_login(
        state,
        "administrator",
        TEST_PASSWORD,
        now=110.0,
    )
    allowed = auth.authenticate_login(
        state,
        "administrator",
        TEST_PASSWORD,
        now=110.0 + auth.LOCKOUT_SECONDS + 1,
    )

    assert blocked.authenticated is False
    assert blocked.public_message == auth.GENERIC_LOGIN_ERROR
    assert allowed.authenticated is True


def test_limiter_state_blocks_rapid_retry_across_sessions(test_credentials):
    limiter_state = {}
    first_session = {}
    second_session = {}

    failed = auth.authenticate_login(
        first_session,
        "administrator",
        "wrong",
        now=100.0,
        limiter_state=limiter_state,
    )
    blocked = auth.authenticate_login(
        second_session,
        "administrator",
        TEST_PASSWORD,
        now=100.1,
        limiter_state=limiter_state,
    )

    assert failed.authenticated is False
    assert blocked.authenticated is False
    assert second_session.get(auth.AUTHENTICATED_KEY) is not True
    assert limiter_state[auth.FAILED_ATTEMPTS_KEY] == 1


def test_successful_login_resets_shared_limiter_state(test_credentials):
    session_state = {}
    limiter_state = {
        auth.FAILED_ATTEMPTS_KEY: 2,
        auth.LAST_FAILED_AT_KEY: 90.0,
    }

    result = auth.authenticate_login(
        session_state,
        "administrator",
        TEST_PASSWORD,
        now=100.0,
        limiter_state=limiter_state,
    )

    assert result.authenticated is True
    assert session_state[auth.AUTHENTICATED_KEY] is True
    assert limiter_state[auth.FAILED_ATTEMPTS_KEY] == 0
    assert auth.LAST_FAILED_AT_KEY not in limiter_state

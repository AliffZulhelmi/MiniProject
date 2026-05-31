"""Authentication helpers for the Streamlit dashboard."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

ADMIN_USERNAME = "administrator"
USERNAME_MAX_LENGTH = 64
PASSWORD_MAX_LENGTH = 256
GENERIC_LOGIN_ERROR = "Invalid username or password."

PASSWORD_HASH_ITERATIONS = 600_000
# Stored verifier material, not a plaintext password.
ADMIN_PASSWORD_SALT_HEX = "d148a0a9f9d9a52c1dd8ae502176c726"  # noqa: S105
ADMIN_PASSWORD_HASH_HEX = (
    "fa466b0cd99d3619a5bac399adc580cb3e1acb3fb5a925105aaa92fecfd109fc"  # noqa: S105
)

AUTHENTICATED_KEY = "auth_authenticated"
SESSION_ID_KEY = "auth_session_id"
LOGIN_AT_KEY = "auth_login_at"
LAST_ACTIVITY_AT_KEY = "auth_last_activity_at"
FAILED_ATTEMPTS_KEY = "auth_failed_attempts"
LAST_FAILED_AT_KEY = "auth_last_failed_at"
LOCKOUT_UNTIL_KEY = "auth_lockout_until"
SERVER_LOGIN_LIMITER: dict[str, object] = {}

MAX_FAILED_ATTEMPTS = 5
FAILED_ATTEMPT_DELAY_SECONDS = 1.0
LOCKOUT_SECONDS = 300.0
IDLE_TIMEOUT_SECONDS = 15 * 60.0
ABSOLUTE_TIMEOUT_SECONDS = 60 * 60.0


@dataclass(frozen=True)
class LoginInput:
    """Normalized login fields after server-side validation."""

    ok: bool
    username: str = ""
    password: str = ""
    public_message: str = GENERIC_LOGIN_ERROR


@dataclass(frozen=True)
class LoginAllowed:
    """Decision for whether a login attempt may proceed."""

    allowed: bool
    public_message: str = ""


@dataclass(frozen=True)
class LoginFailure:
    """Public result for a failed login attempt."""

    public_message: str = GENERIC_LOGIN_ERROR


@dataclass(frozen=True)
class LoginResult:
    """Result of a submitted login form."""

    authenticated: bool
    public_message: str = ""


def validate_login_input(username: object, password: object) -> LoginInput:
    """Validate and normalize login form input."""
    if not isinstance(username, str) or not isinstance(password, str):
        return LoginInput(ok=False)

    normalized_username = username.strip()
    normalized_password = password.strip()
    if (
        not normalized_username
        or not normalized_password
        or len(normalized_username) > USERNAME_MAX_LENGTH
        or len(normalized_password) > PASSWORD_MAX_LENGTH
        or not normalized_username.isprintable()
        or not normalized_password.isprintable()
    ):
        return LoginInput(ok=False)

    return LoginInput(
        ok=True,
        username=normalized_username,
        password=normalized_password,
        public_message="",
    )


def verify_credentials(username: object, password: object) -> bool:
    """Return True only for the configured administrator credential."""
    login_input = validate_login_input(username, password)
    if not login_input.ok or login_input.username != ADMIN_USERNAME:
        return False

    return _verify_password_hash(
        login_input.password,
        salt_hex=ADMIN_PASSWORD_SALT_HEX,
        expected_hash_hex=ADMIN_PASSWORD_HASH_HEX,
        iterations=PASSWORD_HASH_ITERATIONS,
    )


def _verify_password_hash(
    password: str,
    *,
    salt_hex: str,
    expected_hash_hex: str,
    iterations: int,
) -> bool:
    """Verify a password against a PBKDF2-HMAC-SHA256 digest."""
    try:
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(expected_hash_hex)
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
    except (TypeError, ValueError):
        return False

    return hmac.compare_digest(actual_hash, expected_hash)


def authenticate_login(
    state: object,
    username: object,
    password: object,
    now: float | None = None,
    limiter_state: object | None = None,
) -> LoginResult:
    """Validate and authenticate a submitted login attempt."""
    current_time = _current_time(now)
    rate_limit_state = state if limiter_state is None else limiter_state
    allowed = check_login_allowed(rate_limit_state, now=current_time)
    if not allowed.allowed:
        return LoginResult(
            authenticated=False,
            public_message=allowed.public_message or GENERIC_LOGIN_ERROR,
        )

    login_input = validate_login_input(username, password)
    if not login_input.ok:
        failure = record_failed_login(rate_limit_state, now=current_time)
        return LoginResult(authenticated=False, public_message=failure.public_message)

    if verify_credentials(login_input.username, login_input.password):
        mark_authenticated(state, now=current_time)
        reset_login_failures(rate_limit_state)
        return LoginResult(authenticated=True)

    failure = record_failed_login(rate_limit_state, now=current_time)
    return LoginResult(authenticated=False, public_message=failure.public_message)


def require_authentication() -> None:
    """Render a login form and stop the app until the session is authenticated."""
    import streamlit as st

    if is_authenticated(st.session_state):
        return

    st.title("Mini WIDS - Login")
    st.caption("Administrator access is required to open the dashboard.")

    with st.form("login_form", clear_on_submit=True):
        username = st.text_input(
            "Username",
            max_chars=USERNAME_MAX_LENGTH,
            autocomplete="username",
        )
        password = st.text_input(
            "Password",
            type="password",
            max_chars=PASSWORD_MAX_LENGTH,
            autocomplete="current-password",
        )
        submitted = st.form_submit_button("Log in", type="primary")

    if submitted:
        result = authenticate_login(
            st.session_state,
            username,
            password,
            limiter_state=SERVER_LOGIN_LIMITER,
        )
        if result.authenticated:
            st.rerun()
        st.error(result.public_message or GENERIC_LOGIN_ERROR)

    st.stop()


def render_logout_control(state: object) -> None:
    """Render authenticated-user status and logout control."""
    import streamlit as st

    if not _get_bool(state, AUTHENTICATED_KEY):
        return

    st.caption(f"Signed in as `{ADMIN_USERNAME}`")
    if st.button("Log out", key="btn_logout_auth", use_container_width=True):
        logout(state)
        st.rerun()


def check_login_allowed(state: object, now: float | None = None) -> LoginAllowed:
    """Return whether the current session may submit a login attempt."""
    current_time = _current_time(now)
    lockout_until = _get_float(state, LOCKOUT_UNTIL_KEY)
    if lockout_until is not None:
        if current_time < lockout_until:
            return LoginAllowed(allowed=False, public_message=GENERIC_LOGIN_ERROR)
        _set_value(state, FAILED_ATTEMPTS_KEY, 0)
        _pop_value(state, LOCKOUT_UNTIL_KEY)

    last_failed_at = _get_float(state, LAST_FAILED_AT_KEY)
    if (
        last_failed_at is not None
        and current_time - last_failed_at < FAILED_ATTEMPT_DELAY_SECONDS
    ):
        return LoginAllowed(allowed=False, public_message=GENERIC_LOGIN_ERROR)

    return LoginAllowed(allowed=True)


def record_failed_login(state: object, now: float | None = None) -> LoginFailure:
    """Record a failed login and apply temporary lockout when needed."""
    current_time = _current_time(now)
    failed_attempts = _get_int(state, FAILED_ATTEMPTS_KEY) + 1
    _set_value(state, FAILED_ATTEMPTS_KEY, failed_attempts)
    _set_value(state, LAST_FAILED_AT_KEY, current_time)
    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        _set_value(state, LOCKOUT_UNTIL_KEY, current_time + LOCKOUT_SECONDS)
    return LoginFailure()


def reset_login_failures(state: object) -> None:
    """Clear failed login counters without changing authenticated session fields."""
    _set_value(state, FAILED_ATTEMPTS_KEY, 0)
    _pop_value(state, LAST_FAILED_AT_KEY)
    _pop_value(state, LOCKOUT_UNTIL_KEY)


def mark_authenticated(state: object, now: float | None = None) -> None:
    """Mark the Streamlit session as authenticated."""
    current_time = _current_time(now)
    _set_value(state, AUTHENTICATED_KEY, True)
    _set_value(state, SESSION_ID_KEY, secrets.token_urlsafe(32))
    _set_value(state, LOGIN_AT_KEY, current_time)
    _set_value(state, LAST_ACTIVITY_AT_KEY, current_time)
    reset_login_failures(state)


def is_authenticated(state: object, now: float | None = None) -> bool:
    """Return True when the session is authenticated and not expired."""
    if not _get_bool(state, AUTHENTICATED_KEY):
        return False

    current_time = _current_time(now)
    login_at = _get_float(state, LOGIN_AT_KEY)
    last_activity_at = _get_float(state, LAST_ACTIVITY_AT_KEY)
    if login_at is None or last_activity_at is None:
        logout(state)
        return False

    idle_expired = current_time - last_activity_at > IDLE_TIMEOUT_SECONDS
    absolute_expired = current_time - login_at > ABSOLUTE_TIMEOUT_SECONDS
    if idle_expired or absolute_expired:
        logout(state)
        return False

    _set_value(state, LAST_ACTIVITY_AT_KEY, current_time)
    return True


def logout(state: object) -> None:
    """Clear authentication state."""
    _set_value(state, AUTHENTICATED_KEY, False)
    for key in (SESSION_ID_KEY, LOGIN_AT_KEY, LAST_ACTIVITY_AT_KEY):
        _pop_value(state, key)


def _current_time(now: float | None) -> float:
    return time.monotonic() if now is None else float(now)


def _get_value(state: object, key: str, default: object = None) -> object:
    if hasattr(state, "get"):
        return state.get(key, default)
    return getattr(state, key, default)


def _set_value(state: object, key: str, value: object) -> None:
    if hasattr(state, "__setitem__"):
        state[key] = value
    else:
        setattr(state, key, value)


def _pop_value(state: object, key: str) -> None:
    if hasattr(state, "pop"):
        state.pop(key, None)
    elif hasattr(state, key):
        delattr(state, key)


def _get_bool(state: object, key: str) -> bool:
    return bool(_get_value(state, key, False))


def _get_int(state: object, key: str) -> int:
    value = _get_value(state, key, 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _get_float(state: object, key: str) -> float | None:
    value = _get_value(state, key)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

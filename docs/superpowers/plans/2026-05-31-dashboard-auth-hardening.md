# Dashboard Authentication Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a tested username/password authentication gate and common authentication hardening to the Streamlit dashboard.

**Architecture:** Create a pure `mini_wids/ui/auth.py` helper for validation, password verification, rate limiting, lockout, session expiry, and Streamlit rendering. Call the helper from `mini_wids/ui/app.py` before rendering dashboard content. Keep detector, storage, reporting, and config files untouched.

**Tech Stack:** Python standard library security primitives (`hashlib`, `hmac`, `secrets`, `time`), Streamlit session state/forms, pytest.

---

## File Structure

- Create `mini_wids/ui/auth.py`: authentication constants, pure helper functions, session state mutation, and Streamlit login/logout UI.
- Modify `mini_wids/ui/app.py`: import `require_authentication` and call it immediately after `st.set_page_config()`.
- Modify `mini_wids/ui/sidebar.py`: show authenticated status and logout button inside the existing sidebar after login.
- Create `tests/ui/test_auth.py`: unit tests for validation, credential checks, rate limiting, lockout, timeout, and logout.
- Modify `README.md`: add the dashboard login credential note without exposing the plaintext password in implementation details.

## Task 1: Auth Helper Validation And Credential Checking

**Files:**
- Create: `mini_wids/ui/auth.py`
- Test: `tests/ui/test_auth.py`

- [ ] **Step 1: Write failing tests**

```python
def test_validate_login_input_trims_username_and_password():
    result = auth.validate_login_input(" administrator ", " secret ")
    assert result.ok is True
    assert result.username == "administrator"
    assert result.password == "secret"


@pytest.mark.parametrize(
    ("username", "password"),
    [("", "secret"), ("administrator", ""), ("a" * 65, "secret"), ("administrator", "x" * 257)],
)
def test_validate_login_input_rejects_empty_or_oversized_values(username, password):
    result = auth.validate_login_input(username, password)
    assert result.ok is False
    assert result.public_message == auth.GENERIC_LOGIN_ERROR


def test_verify_credentials_accepts_only_administrator_password():
    assert auth.verify_credentials("administrator", ADMIN_PASSWORD) is True
    assert auth.verify_credentials("administrator", "wrong") is False
    assert auth.verify_credentials("someone_else", ADMIN_PASSWORD) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/ui/test_auth.py::test_validate_login_input_trims_username_and_password tests/ui/test_auth.py::test_validate_login_input_rejects_empty_or_oversized_values tests/ui/test_auth.py::test_verify_credentials_accepts_only_administrator_password -q`

Expected: import or attribute failures because `mini_wids.ui.auth` does not exist yet.

- [ ] **Step 3: Implement minimal helper**

Create validation result data, constants, PBKDF2 verification, and generic error handling in `mini_wids/ui/auth.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/ui/test_auth.py::test_validate_login_input_trims_username_and_password tests/ui/test_auth.py::test_validate_login_input_rejects_empty_or_oversized_values tests/ui/test_auth.py::test_verify_credentials_accepts_only_administrator_password -q`

Expected: PASS.

## Task 2: Rate Limit, Lockout, And Session Lifecycle

**Files:**
- Modify: `mini_wids/ui/auth.py`
- Test: `tests/ui/test_auth.py`

- [ ] **Step 1: Write failing tests**

```python
def test_rate_limit_blocks_rapid_failed_retry():
    state = {}
    first = auth.record_failed_login(state, now=100.0)
    second = auth.check_login_allowed(state, now=100.1)
    assert first.public_message == auth.GENERIC_LOGIN_ERROR
    assert second.allowed is False


def test_failed_attempts_trigger_lockout():
    state = {}
    for offset in range(auth.MAX_FAILED_ATTEMPTS):
        auth.record_failed_login(state, now=100.0 + offset + auth.FAILED_ATTEMPT_DELAY_SECONDS)
    result = auth.check_login_allowed(state, now=110.0)
    assert result.allowed is False
    assert result.public_message == auth.GENERIC_LOGIN_ERROR


def test_session_idle_and_absolute_timeout_clear_auth_state():
    state = {}
    auth.mark_authenticated(state, now=100.0)
    assert auth.is_authenticated(state, now=100.0 + auth.IDLE_TIMEOUT_SECONDS - 1) is True
    assert auth.is_authenticated(state, now=100.0 + auth.IDLE_TIMEOUT_SECONDS + 1) is False

    auth.mark_authenticated(state, now=200.0)
    assert auth.is_authenticated(state, now=200.0 + auth.ABSOLUTE_TIMEOUT_SECONDS + 1) is False


def test_logout_clears_authentication_state():
    state = {}
    auth.mark_authenticated(state, now=100.0)
    auth.logout(state)
    assert state.get(auth.AUTHENTICATED_KEY) is False
    assert auth.SESSION_ID_KEY not in state
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/ui/test_auth.py::test_rate_limit_blocks_rapid_failed_retry tests/ui/test_auth.py::test_failed_attempts_trigger_lockout tests/ui/test_auth.py::test_session_idle_and_absolute_timeout_clear_auth_state tests/ui/test_auth.py::test_logout_clears_authentication_state -q`

Expected: attribute failures for lifecycle helpers.

- [ ] **Step 3: Implement lifecycle helpers**

Add `check_login_allowed`, `record_failed_login`, `mark_authenticated`, `is_authenticated`, and `logout` with session keys in `auth.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/ui/test_auth.py::test_rate_limit_blocks_rapid_failed_retry tests/ui/test_auth.py::test_failed_attempts_trigger_lockout tests/ui/test_auth.py::test_session_idle_and_absolute_timeout_clear_auth_state tests/ui/test_auth.py::test_logout_clears_authentication_state -q`

Expected: PASS.

## Task 3: Streamlit Login Gate Wiring

**Files:**
- Modify: `mini_wids/ui/auth.py`
- Modify: `mini_wids/ui/app.py`
- Modify: `mini_wids/ui/sidebar.py`
- Test: `tests/ui/test_auth.py`

- [ ] **Step 1: Write failing test**

```python
def test_successful_login_resets_failed_attempts_and_sets_session():
    state = {auth.FAILED_ATTEMPTS_KEY: 2, auth.LAST_FAILED_AT_KEY: 99.0}
    result = auth.authenticate_login(state, " administrator ", ADMIN_PASSWORD, now=100.0)
    assert result.authenticated is True
    assert state[auth.AUTHENTICATED_KEY] is True
    assert auth.SESSION_ID_KEY in state
    assert state[auth.FAILED_ATTEMPTS_KEY] == 0
    assert auth.LAST_FAILED_AT_KEY not in state
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/ui/test_auth.py::test_successful_login_resets_failed_attempts_and_sets_session -q`

Expected: `authenticate_login` is missing.

- [ ] **Step 3: Implement login orchestration and Streamlit rendering**

Add `authenticate_login`, `require_authentication`, and `render_logout_control`. Wire `require_authentication()` into `app.py` after `st.set_page_config()`. Wire `render_logout_control(st.session_state)` into the sidebar.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/ui/test_auth.py::test_successful_login_resets_failed_attempts_and_sets_session -q`

Expected: PASS.

## Task 4: Documentation And Full Verification

**Files:**
- Modify: `README.md`
- Test: all tests

- [ ] **Step 1: Update usage docs**

Add a short Dashboard Login section describing the username, no signup flow, session timeout behavior, and that the password is verified through a non-reversible hash.

- [ ] **Step 2: Run full tests**

Run: `pytest`

Expected: all tests pass.

- [ ] **Step 3: Run formatter/checker**

Run: `python -m ruff check mini_wids tests`

Expected: no lint failures.

- [ ] **Step 4: Manual dashboard check**

Run: `streamlit run mini_wids/ui/app.py`

Expected: login form appears first, password is masked, valid credentials show the dashboard, logout returns to login, repeated bad attempts trigger lockout.

## Self-Review

Spec coverage:
- Login gate: Task 3.
- No signup: Task 3 and README.
- Server/client validation: Task 1 and Task 3.
- Timeout session: Task 2.
- Password protection: Task 1.
- Rate limit and lockout: Task 2.
- Common authentication vulnerability tests: Tasks 1 through 3.

Placeholder scan: no placeholders remain.

Type consistency: all planned helpers live in `mini_wids.ui.auth`; tests import that module directly.

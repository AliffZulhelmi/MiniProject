# Dashboard Authentication Hardening Design

## Goal

Protect the Streamlit dashboard with a single administrator login and add
defenses for common authentication attacks. The CLI detector flow remains
unchanged.

## Scope

In scope:
- `mini_wids/ui/app.py` authentication gate.
- A new `mini_wids/ui/auth.py` helper module.
- Unit tests under `tests/ui/`.
- README usage notes for login behavior.

Out of scope:
- Signup, password reset, roles, MFA, and user management.
- Changes to detector logic, storage persistence, reporting, or `config/*.yml`.
- Network-level TLS termination, since this app is launched with Streamlit.

## Credentials

There is exactly one valid username: `administrator`.
The password supplied by the project owner is verified through a stored salted
PBKDF2-HMAC-SHA256 hash, not stored as plaintext. Environment overrides may be
supported for local deployment, but the default code path must work without a
signup or setup flow.

## Authentication Flow

The dashboard calls `require_authentication()` immediately after
`st.set_page_config()`. If the session is not authenticated, the helper renders a
login form and stops the Streamlit run with `st.stop()`. On successful login, it
sets authenticated session fields and reruns the app. On logout, it clears the
auth fields and reruns.

Inputs are validated before credential comparison:
- Username and password must be strings.
- Leading and trailing whitespace is stripped.
- Empty values are rejected.
- Username length is capped.
- Password length is capped to avoid resource exhaustion.
- The failure message is generic for bad username, bad password, locked account,
  and malformed input.

## Session Security

The session stores:
- An authenticated flag.
- A cryptographically random session ID.
- Login time.
- Last activity time.

The session expires after an idle timeout and after an absolute lifetime. Expired
sessions are cleared before the dashboard renders. The sidebar displays a simple
logged-in status and logout button after authentication.

## Brute Force And Rate Limiting

Failed login attempts are tracked in Streamlit session state. The first few
failures are allowed, then the session is temporarily locked. A minimum delay is
also enforced between failed attempts. The user sees one generic error message,
which avoids confirming whether the username exists.

## Password Protection

Password verification uses `hashlib.pbkdf2_hmac` with SHA-256, a fixed salt for
the single built-in credential, and a high iteration count. Digest comparison
uses `hmac.compare_digest` to avoid timing leaks. The app does not implement
reversible password encryption because passwords should be hashed, not
decrypted.

## Client And Server Validation

Streamlit provides the client form controls:
- Username text input with max length.
- Password input with masked entry and max length.
- Submit button inside `st.form`.

Server-side validation is authoritative and lives in pure helper functions so it
can be tested without Streamlit.

## Testing

Unit tests cover:
- Correct login succeeds.
- Wrong username and wrong password fail with the same public result.
- Empty and malformed inputs are rejected.
- Whitespace is normalized.
- Excessively long inputs are rejected before hash verification.
- Repeated failures trigger lockout.
- Rate limiting blocks rapid retries.
- Idle timeout and absolute timeout clear the authenticated session.
- Logout clears all authentication state.

Manual validation covers:
- Dashboard shows only the login form before authentication.
- Password input is masked.
- Successful login shows the dashboard.
- Logout returns to the login form.
- Repeated failures trigger a lockout message without revealing which field was
  wrong.

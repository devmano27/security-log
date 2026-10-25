# 🔐 SecureAuth Lab: Authentication Hardening + Configuration Audit

A beginner-friendly defensive security portfolio project in two connected parts:

1. **A hardened Flask login system** (password hashing, CSRF protection, rate limiting, session controls, security headers).
2. **A read-only audit tool (`audit.py`)** that checks the host *and this project's own configuration* (secret strength, cookie flags, Git ignore rules) and exports a JSON report.

A written **STRIDE threat model** ties them together: every threat maps to a mitigation and to a test that checks it.

> **Scope:** a learning lab for localhost. It is not a production identity system and must not be exposed to the public internet as-is.

## How the pieces fit

```text
 Threat model (docs/)  ──►  Mitigations in app.py  ──►  Automated tests (tests/)
         │                                                     
         └────────────►  audit.py checks the configuration those mitigations depend on
                         (SECRET_KEY, COOKIE_SECURE, .gitignore, firewall, open ports)
```

## Features

**Application**
- Password hashing with Werkzeug; no plaintext storage
- Username allowlist, 12-character minimum password, confirmation, unique usernames (case-insensitive)
- Parameterized SQL queries
- CSRF protection on every POST (including logout)
- Rate limiting on login and registration (5 POSTs/minute)
- Session cleared on login and logout, 30-minute lifetime
- HttpOnly + SameSite=Lax cookies, optional Secure flag
- CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, `no-store` caching
- Same error message for unknown user and wrong password

**Audit tool** (standard library only, read-only)
- Host firewall status (Windows, Linux/UFW, macOS)
- Loopback port check for common services plus the Flask dev port
- Project checks: `SECRET_KEY` length and placeholder detection (value never printed), `COOKIE_SECURE`, rate-limit backend, `.env` permissions, `.env` and database in `.gitignore`, dependency bounds
- Reports `unknown` instead of guessing when a check can't run

## Requirements

- Python 3.10+
- pip

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/secure-auth-lab.git
cd secure-auth-lab

python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
# macOS / Linux:       source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env            # Windows: Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste into SECRET_KEY in .env

python app.py                   # http://127.0.0.1:5000
```

## Run the audit

```bash
python audit.py                                  # writes reports/secureconfig-report.json
python audit.py --output reports/my-audit.json
```

Reports contain host details and are ignored by Git (only `reports/sample-report.json` is tracked). Review before sharing.

## Run the tests

```bash
pytest -q
```

- `tests/test_auth.py`: registration, hashing, login, sessions, headers, cookies, plus **CSRF rejection and rate-limit (429) tests that run with those controls enabled**.
- `tests/test_audit.py`: secret-strength detection, Git-ignore checks, port detection, report output, and a regression test for the UFW `inactive` vs `active` parsing bug.

Run the suite yourself and only claim a control works after you see the test pass.

## Manual security checklist

- [ ] Register, then confirm the database holds a hash, not your password
- [ ] A wrong password creates no session
- [ ] `/dashboard` without signing in returns 401
- [ ] Logout clears the session
- [ ] Repeated login POSTs return HTTP 429
- [ ] Response headers visible in browser dev tools
- [ ] `git status` shows neither `.env` nor `auth_lab.db`
- [ ] `python audit.py` reports no unexpected `review` items

See [`docs/secure-configuration-checklist.md`](docs/secure-configuration-checklist.md).

## Configuration

| Variable | Purpose | Example |
|---|---|---|
| `SECRET_KEY` | Signs sessions and CSRF tokens | 32+ random bytes |
| `COOKIE_SECURE` | Secure cookies | `0` on localhost HTTP, `1` behind HTTPS |
| `DATABASE_PATH` | SQLite path | `auth_lab.db` |
| `RATELIMIT_STORAGE_URI` | Rate-limit backend | `memory://` locally, Redis for multi-process |

## Project structure

```text
secure-auth-lab/
├── app.py                  # Flask application
├── audit.py                # Host + project configuration audit
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
├── pytest.ini
├── templates/              # base, login, register, dashboard, 401, error
├── static/css/style.css
├── tests/                  # conftest.py, test_auth.py, test_audit.py
├── docs/
│   ├── threat-model.md
│   └── secure-configuration-checklist.md
└── reports/
    └── sample-report.json
```

## Limitations and next steps

- Add audit logging for authentication events (a gap called out in the threat model)
- Serve over HTTPS with a production WSGI server and set `COOKIE_SECURE=1`
- Use shared rate-limit storage (Redis) and account lockout policy
- Add MFA, email verification, and account recovery
- Consider Argon2id with a maintained library
- Add dependency scanning (`pip-audit`) to CI
- Add an HTML view of the audit report

## Responsible use

Test only this application and systems you own or have explicit permission to assess. Use made-up credentials for every demonstration. The audit tool inspects only the machine it runs on.

## License

MIT. See [`LICENSE`](LICENSE) (replace `YOUR NAME`).

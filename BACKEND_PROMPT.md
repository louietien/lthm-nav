# Backend prompt — lthm-nav

## Context

This repo (`lthm-nav`) is a private navigation hub at `nav.lthm.dk`. It links to three personal tools:

- **lthm.dk** — Flask resume/portfolio (Python)
- **stats.lthm.dk** — Activity tracker (TypeScript + Hono + Cloudflare Workers)
- **split.lthm.dk** — Expense splitter (part of the Flask app)

The frontend is a single static `index.html` file (already written). It uses the shared design system: warm beige/rust palette, DM Sans font, light/dark theming via `data-theme` on `<html>`.

## Task

Build a minimal backend to serve `index.html` behind **passkey authentication**, consistent with the pattern already used in `lthm-resume` (`app.py`).

## Requirements

### Stack
Match the existing lthm-resume stack: **Python + Flask**. Reuse the same patterns from `lthm-resume/app.py` wherever possible.

### Authentication
- Protect `GET /` with passkey auth (WebAuthn). Unauthenticated requests redirect to a login page.
- The login page should match the existing style: same CSS tokens, same `panel`/`badge`/`lock-button` classes, DM Sans font.
- Reuse the passkey registration and authentication logic from `lthm-resume/app.py` — the `passkeys` table schema and `/passkeys/*` routes are the reference implementation.
- Store sessions in a signed cookie (Flask `session`), same as lthm-resume.

### Routes
| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/`  | Serve `index.html` (requires auth) |
| `GET`  | `/login` | Passkey login page |
| `POST` | `/passkeys/authenticate/begin` | WebAuthn assertion begin |
| `POST` | `/passkeys/authenticate/complete` | WebAuthn assertion complete → set session |
| `POST` | `/logout` | Clear session, redirect to `/login` |

### CSRF & security
- CSRF token on the logout form (same pattern as lthm-resume).
- `SECRET_KEY` loaded from env.
- `RP_ID` and `RP_NAME` configurable from env (`NAV_RP_ID`, `NAV_RP_NAME`), defaulting to `nav.lthm.dk`.

### Database
- SQLite via `sqlite3` (no ORM), same as lthm-resume.
- Single table: `passkeys(id, credential_id, public_key, sign_count, created_at)`.

### Static files
- Serve `index.html` at `/` when authenticated.
- No other static assets needed — all CSS is inline in `index.html`.

### Deployment
- Designed to run on a VPS behind nginx (same setup as lthm.dk).
- `requirements.txt` with pinned versions.
- `wsgi.py` entry point for gunicorn.

## Reference files
- Auth logic: `lthm-resume/app.py` — search for `passkey`, `authenticate`, `register`, `_get_db`.
- Login page HTML pattern: `lthm-resume/templates/nav.html` — the `.login-wrap.panel` layout.
- CSS tokens: already inlined in `lthm-nav/index.html` — do not add an external stylesheet.

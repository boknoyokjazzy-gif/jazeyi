# JAZEYI — site + private client messaging

Folder contents:

| File          | What it is                                                        |
|---------------|-------------------------------------------------------------------|
| `index.html`  | Your portfolio + "Start Conversation" form                        |
| `chat.html`   | Visitor chat page (opened via each conversation's secret link)    |
| `admin.html`  | Your private owner dashboard (password protected)                 |
| `server.py`   | The backend — serves everything, JSON API, auth, rate limiting    |
| `chat.db`     | SQLite database (created automatically — keep it private!)        |

## Run it locally

```bash
python3 server.py
```
Open http://localhost:8000 — dashboard at http://localhost:8000/admin

## Required before going public

Set your own admin password (otherwise one is generated and printed to the console on first run):

```bash
export JZ_ADMIN_PASSWORD="pick-something-strong"
python3 server.py
```

## Deploying (examples)

This app needs a host that can run *processes* (Netlify/Drop-style static hosts can't).

- **Render**: new Web Service → build command: none → start command: `python3 server.py` → add a disk mounted at the project root (so `chat.db` survives restarts) → set env `JZ_PORT=10000` (Render assigns it; or use `$PORT`) and `JZ_ADMIN_PASSWORD`.
- **Fly.io / Railway / a VPS**: same idea — start command `python3 server.py`, attach a volume for `chat.db`.
- Set `JZ_PUBLIC_URL=https://your-domain.com` so recovery emails contain correct links.

## Optional: password-reset emails (link recovery)

Without SMTP, "recover my link" answers generically and logs the request to the server console (no email is sent). To actually email recovery links, set:

```
JZ_SMTP_HOST=smtp.gmail.com
JZ_SMTP_PORT=587
JZ_SMTP_USER=you@gmail.com
JZ_SMTP_PASS=your-app-password    # Gmail: Settings → Security → App Passwords
JZ_SMTP_FROM=you@gmail.com
```

## How it works / security

- Visitors fill the form on the homepage → a conversation row is created with a **192-bit random token**. The link `/chat#TOKEN` is their only way back — it travels in the URL hash (never sent to servers/logs).
- All chat APIs are **server-side authorized**: visitors can only read/write their own thread via their token; the dashboard checks a hashed, HttpOnly session cookie (7-day expiry, SameSite=Lax).
- Rate limiting per IP (new conversations, messages, logins) + honeypot + minimum-fill-time traps on the form.
- Inputs are length-limited and sanitized; the front-ends render all text via `textContent` (no HTML injection).
- `chat.db` holds all conversations — don't commit it to a public repo. Add to `.gitignore`.

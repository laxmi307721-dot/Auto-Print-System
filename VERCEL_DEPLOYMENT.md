# Deploying to Vercel

The Flask app uses Vercel's Python function runtime. Print requests and uploaded
files are stored in Supabase so they survive separate serverless invocations;
the Windows print agent downloads approved jobs from Supabase through a
short-lived signed URL.

## 1. Prepare Supabase

1. Create a Supabase project.
2. Run [`supabase/schema.sql`](./supabase/schema.sql) in the Supabase SQL editor.
   This creates the `print_jobs` table and a private `print-files` bucket.
3. Copy the project URL and the **service role** key from the Supabase API
   settings. The service role key must only be configured as a Vercel secret;
   never put it in browser code or commit it.

## 2. Configure Vercel

Import this repository into Vercel with the project root as the root directory.
Vercel detects the root [`app.py`](./app.py) Flask entrypoint; the checked-in
[`vercel.json`](./vercel.json) sets the function duration. Static logo assets
are served from [`public/static/`](./public/static).
Set these environment variables for Production (and Preview if you use it):

| Variable | Value |
| --- | --- |
| `PUBLIC_MODE` | `1` |
| `FLASK_SECRET_KEY` | A persistent random secret; generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `ADMIN_PASSWORD_HASH` | Werkzeug password hash; generate with `python -c "import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass.getpass()))"` |
| `PRINT_AGENT_TOKEN` | A persistent random secret of at least 32 characters; generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `SUPABASE_URL` | Your Supabase project URL, beginning with `https://` |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key |
| `SUPABASE_STORAGE_BUCKET` | `print-files` (optional if unchanged) |
| `RATELIMIT_STORAGE_URI` | A Redis TLS URL (`rediss://...`) from an Upstash Redis database, for shared rate limits |
| `ADMIN_PHONE_NUMBER` | Registered admin mobile number, in 10-digit or `91` + 10-digit format |
| `WHATSAPP_ACCESS_TOKEN` | Meta WhatsApp Cloud API token |
| `WHATSAPP_PHONE_NUMBER_ID` | Meta WhatsApp sender phone-number ID |
| `WHATSAPP_OTP_TEMPLATE` | Approved WhatsApp template with one body text parameter for the OTP |

Create an Upstash Redis database (or another TLS-enabled Redis service) and set
its connection URL as `RATELIMIT_STORAGE_URI`; Vercel instances cannot safely
share the default in-memory rate-limit counters.

Create an approved WhatsApp template whose body accepts one OTP parameter.
The registered number is configured with `ADMIN_PHONE_NUMBER`; only that
number can request a recovery OTP. Redis stores the short-lived challenge,
cooldown, and a reset password hash so OTP recovery works across serverless
instances. The original password is never displayed. After successful OTP
verification, choose a new password and sign in with it. The Redis database
must remain available for recovered passwords to remain active.

Deploy after setting the variables. Do not use the temporary/default admin
password. If `ADMIN_PASSWORD_HASH` is later changed, that new environment hash
replaces the Redis-stored override until the password is reset again.

## 3. Connect the Windows print agent

Install the project's Python requirements and configure the agent machine with:

```powershell
$env:PRINT_SERVER_URL = "https://your-project.vercel.app"
$env:PRINT_AGENT_TOKEN = "the-same-value-as-the-vercel-variable"
python .\print_agent.py
```

Keep the token private. The agent downloads each approved PDF to a temporary
local file, submits the result, and retries the queue if printing or download
fails.

## Runtime constraints

- Vercel's request-body limit is smaller than the app's local 50 MiB upload
  limit. The Vercel function therefore enforces a 4 MiB upload limit.
- Uploaded files and print jobs are durable in Supabase. Temporary PDF
  processing uses Vercel's `/tmp` directory only during a request.
- Printing still requires the Windows agent to be online and a printer
  configured on that machine.

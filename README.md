# DataShadow

DataShadow is a limited website configuration and privacy policy inspector. It checks public HTTP(S) endpoints, TLS certificate validation, HTTPS redirect behavior, selected security headers, response status, and selected wording in a linked privacy policy. It does not attempt exploitation and cannot certify that a website is safe, compliant, or following its policy.

## Requirements and setup

- Node.js 20 or newer (developed with Node.js 24.18.1)
- MongoDB local or MongoDB Atlas

Install dependencies with `npm install`. Copy `.env.example` to `.env` and set `MONGODB_URI`, `DB_NAME`, and optionally `PORT`. The server does not load `.env` automatically: in PowerShell, set environment variables before starting, or use a local environment-file runner of your choice. Example:

```powershell
$env:MONGODB_URI = 'mongodb://127.0.0.1:27017'
$env:DB_NAME = 'datashadow'
$env:PORT = '3000'
npm start
```

For Atlas, use the connection URI from your Atlas project as `MONGODB_URI`, ensure the database user has read/write access, and allow the machine's network address in Atlas Network Access. Never commit `.env` or credentials. Open <http://localhost:3000>.

## API

- `GET /api/health` — server and MongoDB connectivity status.
- `POST /api/auth/register` — JSON `{ "email": "you@example.com", "password": "at-least-10-characters" }`; creates an account and signs in.
- `POST /api/auth/login` — verifies credentials and creates a session.
- `POST /api/auth/logout` — revokes the current session.
- `GET /api/auth/me` — returns the current signed-in account.
- `POST /api/scan` — signed-in JSON `{ "url": "https://example.com", "expectedDomain": "example.com" }`; scans a site, optionally evaluates domain similarity, and saves to the account's history.
- `GET /api/scans` — latest 100 saved scan summaries.
- `GET /api/scans/:id` — full saved report.
- `DELETE /api/scans/:id` — delete a saved report.
- `GET /api/scans/:id/compare/:otherId` — compare same-hostname reports.
- `POST /api/compare` — JSON `{ "urls": ["https://one.example", "https://two.example"] }`; performs two live scans and returns side-by-side reports.
- `GET /api/privacy-policy?url=https%3A%2F%2Fexample.com` — run policy discovery and return per-topic wording matches.

All API responses are JSON. The database uses a `scans` collection with hostname and scan-time indexes. Responses and request bodies are size-limited; outbound requests have timeouts and at most four redirects.

## Accounts and report privacy

Sign in or create an account before using scans and history. Passwords are stored as salted scrypt hashes; the original password is never stored. Sessions use a random opaque token in an HttpOnly, SameSite=Lax cookie, while MongoDB stores only its SHA-256 hash and expiry. In production (`NODE_ENV=production`) the cookie is marked Secure and should be served over HTTPS. Scan records include an account owner ID, and history, report reads, deletes, and saved comparisons are filtered by that owner. Requests that change data check the request origin. Account and scan attempts are rate-limited.

This demo does not yet include email verification, password reset, or multi-factor authentication. MongoDB must be available to sign in and validate account sessions.

## Scanner safeguards and limits

Only HTTP(S) is accepted. Hostnames are resolved before each outbound request; every returned address must pass public-address checks, and the selected validated address is pinned for that connection. Redirects are parsed, revalidated, and resolved again. Loopback, private, link-local, reserved, and non-global IPv6 ranges are rejected. Response bodies are capped. TLS verification is enabled. A denied target or an unsupported edge case is reported as an error/UNKNOWN, never fetched unrestricted.

This is a best-effort MVP, not a formal security product. A scan uses a shared eight-second request budget, a 4.5-second per-request cap, and a 300 KB page limit to return promptly; a slow page or policy can therefore be UNKNOWN. Public IP classification intentionally fails closed for unusual IPv6 ranges. Some complex pages, JavaScript-rendered policy links, unusual encodings, and policy formats are not analyzed. A policy's detected statements do not prove actual practices. HTTPS alone and missing headers do not determine overall safety.

The limited configuration indicator is shown from 0 to 100 after at least four of eight connection and configuration checks complete. The formula combines connection (40%), security configuration (40%), and observable response behavior (20%); PASS contributes 100, REVIEW 50, FAIL 0, and UNKNOWN is omitted. Missing categories are omitted and remaining category weights are normalized. Privacy policy results are shown separately as coverage of ten selected wording topics and never affect the indicator. Neither number is a probability of safety or a measure of actual privacy quality.

## Quick verification checklist

1. Start MongoDB, run `npm start`, and visit `/api/health`; expect `database: connected`.
2. Scan `https://example.com`; inspect PASS/REVIEW/UNKNOWN findings and the saved history.
3. Try malformed URLs and `http://127.0.0.1`; expect validation or SSRF rejection.
4. Open a saved report, compare two reports for the same host, then delete one.
5. Stop MongoDB; `/api/health` should report it disconnected and account operations should explain that authentication needs the database. The server retries the MongoDB connection in the background.
6. Run `npm test` for URL/SSRF validation, policy analysis, score coverage, domain similarity, scan limits, normalization, and report-diff checks.

## Hackathon experience

Reports include category-level evidence coverage, confidence/severity, expandable technical evidence, policy-topic excerpts, prioritized next steps, and Nginx/Node.js fix examples for selected headers. Use the comparison lab for two live sites, or compare saved scans of the same hostname to review header, redirect, policy fingerprint, and finding changes. Save a standalone HTML report, JSON evidence, or use Print / PDF. The Learn section explains the limits of each signal and includes an interactive policy-text quiz. The scanner rate-limits to eight site checks per client address each minute (a two-site comparison uses two checks).

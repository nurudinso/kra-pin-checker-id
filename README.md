# KRA PIN Checker

Ready-made integration for the **Kenya Revenue Authority (KRA) PIN Checker API**: send a taxpayer ID (National ID or business reg number), get back the KRA PIN and taxpayer name.

Includes a small Node server with a web UI, a CLI script, and a Postman collection. No `.env` or secrets are committed—add your own credentials locally.

---

## Quick start

1. **Get credentials** — Consumer Key and Consumer Secret from KRA (e.g. developer portal / GavaConnect).

2. **Configure**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and set `KRA_CLIENT_ID` and `KRA_CLIENT_SECRET`.

3. **Run**
   ```bash
   node server.js
   ```
   Open **http://localhost:3000** and use the form, or run the CLI:
   ```bash
   node run-kra-pin-checker.js <taxpayer-id> [INDIVIDUAL|NONINDIVIDUAL]
   ```

Requires **Node 18+**. Never commit `.env` (it’s in `.gitignore`).

---

## Env vars

| Variable | Required | Description |
|----------|----------|-------------|
| `KRA_CLIENT_ID` | Yes | Consumer Key |
| `KRA_CLIENT_SECRET` | Yes | Consumer Secret |
| `KRA_BASE_URL` | No | Default `https://api.kra.go.ke` |
| `KRA_TOKEN_URL` | No | Token endpoint (default: `…/oauth/token`) |
| `KRA_CHECKER_URL` | No | Checker endpoint (default: `…/checker/v1/pin`) |
| `PORT` | No | Web server port (default 3000) |

---

## Disclaimer

This project is for **integration and reference only**. You are responsible for using KRA APIs in line with KRA’s terms, applicable laws, and data-protection rules. Misuse of taxpayer data or the APIs (e.g. unauthorised access, resale of data, or use beyond what your credentials allow) may have legal consequences under Kenyan law, including the [Tax Procedures Act](https://new.kenyalaw.org/akn/ke/act/2019/24/eng@2022-12-31). Use at your own risk; no warranty is provided.

---

## Docs

- **Integration guide** (how it works, examples for NestJS, Node, Python, PHP, Go): see **[INTEGRATION.md](./INTEGRATION.md)**.

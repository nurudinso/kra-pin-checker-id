# Testing KRA FIN Checker by PIN

This folder contains scripts to test the **FIN Checker by PIN** API from the KRA/DevGateway docs.

## API summary

- **Method:** POST  
- **Path:** `/api/fin-checker`  
- **Body:** `{ "pin": "<national-id>" }` (e.g. `"20180909-001"`)  
- **Headers:** `Content-Type: application/json`, `Accept: application/json`

## Quick test (curl)

```bash
# Set your real API base URL, then run:
export KRA_API_BASE_URL=https://your-devgateway-or-api-host.com
./test-fin-checker.sh

# Or with a specific PIN:
./test-fin-checker.sh "20180909-001"
```

## Quick test (Node)

```bash
# Requires Node 18+ (for native fetch)
KRA_API_BASE_URL=https://your-api.com node test-fin-checker.js
node test-fin-checker.js "20180909-001"
```

## Expected responses

**Success (200):**
```json
{
  "status": "OK",
  "message": "Request processed successfully",
  "data": {
    "fin": "20180909-001",
    "found": true,
    "status": "Active"
  }
}
```

**Error (e.g. 400):**
```json
{
  "status": "ERROR",
  "message": "Invalid input",
  "errors": [{ "field": "pin", "message": "PIN format is incorrect" }]
}
```

Replace `https://api.example.com` (or the default in the scripts) with your actual KRA/DevGateway base URL before running.

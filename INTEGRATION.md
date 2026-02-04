# KRA PIN Checker — integration guide

This doc explains how the API flow works and how to plug it into your own stack (NestJS, Node, Python, PHP, Go). The repo’s README has the quick start for the included server and CLI.

**Disclaimer:** Use KRA APIs in line with KRA’s terms and applicable law (including the [Tax Procedures Act](https://new.kenyalaw.org/akn/ke/act/2019/24/eng@2022-12-31)). Misuse may have legal consequences. See the [README](./README.md#disclaimer) for the full disclaimer.

---

## How it works

The KRA API uses OAuth2 client credentials:

1. **Get a token** — Call the token endpoint with your Consumer Key and Consumer Secret (Basic auth). You get back an `access_token` that lasts about an hour.
2. **Call the PIN checker** — Send that token as a Bearer token and a JSON body with the taxpayer ID and type (individual vs company). The response gives you the PIN and taxpayer name (when found).

So in practice: **authenticate once (and cache the token), then call the checker whenever you need to resolve an ID to a PIN.**

**Important:** The ID you send is *not* the PIN. It’s the National ID (for individuals) or Business Registration Number (for companies). The API returns the actual KRA PIN.

---

## Endpoints (production)

- **Token:** `POST https://api.kra.go.ke/oauth/token`  
  Headers: `Authorization: Basic <base64(ConsumerKey:ConsumerSecret)>`, `Content-Type: application/x-www-form-urlencoded`  
  Body: `grant_type=client_credentials`

- **Checker:** `POST https://api.kra.go.ke/checker/v1/pin`  
  Headers: `Authorization: Bearer <access_token>`, `Content-Type: application/json`  
  Body: `{ "TaxpayerType": "KE" | "COMP", "TaxpayerID": "<id>" }`  
  - `KE` = individual (National ID)  
  - `COMP` = company (Business Reg No)

---

## Request / response reference

**Checker request body**

| Field          | Type   | Description                                  |
|----------------|--------|----------------------------------------------|
| `TaxpayerType` | string | `"KE"` (individual) or `"COMP"` (company)    |
| `TaxpayerID`   | string | National ID or business registration number  |

**Success response** (field names may vary)

- PIN: `TaxpayerPIN` or `pin`
- Name: `TaxpayerName` or `taxpayerName`

**Errors** — Check HTTP status (400, 401, 404, 500) and the response body for `ErrorMessage` or similar.

---

## Integration examples

Use your own env vars or config for `KRA_CLIENT_ID`, `KRA_CLIENT_SECRET`, and optional `KRA_BASE_URL` / `KRA_TOKEN_URL` / `KRA_CHECKER_URL`. In production, cache the token and reuse it until a few minutes before expiry.

---

### Node (plain)

```javascript
const baseUrl = process.env.KRA_BASE_URL || 'https://api.kra.go.ke';
const tokenUrl = process.env.KRA_TOKEN_URL || `${baseUrl}/oauth/token`;
const checkerUrl = process.env.KRA_CHECKER_URL || `${baseUrl}/checker/v1/pin`;

async function getToken() {
  const auth = Buffer.from(
    `${process.env.KRA_CLIENT_ID}:${process.env.KRA_CLIENT_SECRET}`
  ).toString('base64');
  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });
  if (!res.ok) throw new Error(`Token: ${res.status}`);
  const data = await res.json();
  return data.access_token;
}

async function checkPin(taxpayerId, isIndividual = true) {
  const token = await getToken();
  const res = await fetch(checkerUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      TaxpayerType: isIndividual ? 'KE' : 'COMP',
      TaxpayerID: String(taxpayerId),
    }),
  });
  if (!res.ok) throw new Error(`Checker: ${res.status}`);
  return res.json();
}

checkPin('12345678', true).then(console.log).catch(console.error);
```

---

### NestJS

```typescript
// kra-pin.service.ts
import { Injectable } from '@nestjs/common';

@Injectable()
export class KraPinService {
  private readonly baseUrl = process.env.KRA_BASE_URL || 'https://api.kra.go.ke';
  private readonly tokenUrl = process.env.KRA_TOKEN_URL || `${this.baseUrl}/oauth/token`;
  private readonly checkerUrl = process.env.KRA_CHECKER_URL || `${this.baseUrl}/checker/v1/pin`;
  private cachedToken: string | null = null;
  private tokenExpiry = 0;
  private readonly CACHE_MS = 55 * 60 * 1000;

  private async getToken(): Promise<string> {
    if (this.cachedToken && Date.now() < this.tokenExpiry) return this.cachedToken;
    const auth = Buffer.from(
      `${process.env.KRA_CLIENT_ID}:${process.env.KRA_CLIENT_SECRET}`,
    ).toString('base64');
    const res = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
    });
    if (!res.ok) throw new Error(`KRA token failed: ${res.status}`);
    const data = await res.json();
    this.cachedToken = data.access_token;
    this.tokenExpiry = Date.now() + this.CACHE_MS;
    return this.cachedToken;
  }

  async checkPin(taxpayerId: string, individual = true): Promise<{ TaxpayerPIN?: string; TaxpayerName?: string }> {
    const token = await this.getToken();
    const res = await fetch(this.checkerUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        TaxpayerType: individual ? 'KE' : 'COMP',
        TaxpayerID: taxpayerId,
      }),
    });
    if (!res.ok) throw new Error(`KRA checker failed: ${res.status}`);
    return res.json();
  }
}
```

Register the service in your module and inject it where you need to verify a PIN.

---

### Python

```python
import os
import base64
import json
import urllib.request

KRA_BASE = os.environ.get("KRA_BASE_URL", "https://api.kra.go.ke")
TOKEN_URL = os.environ.get("KRA_TOKEN_URL", f"{KRA_BASE}/oauth/token")
CHECKER_URL = os.environ.get("KRA_CHECKER_URL", f"{KRA_BASE}/checker/v1/pin")

def get_token():
    key = os.environ["KRA_CLIENT_ID"]
    secret = os.environ["KRA_CLIENT_SECRET"]
    auth = base64.b64encode(f"{key}:{secret}".encode()).decode()
    req = urllib.request.Request(
        TOKEN_URL,
        data=b"grant_type=client_credentials",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read().decode())
    return data["access_token"]

def check_pin(taxpayer_id: str, individual: bool = True) -> dict:
    token = get_token()
    body = json.dumps({
        "TaxpayerType": "KE" if individual else "COMP",
        "TaxpayerID": taxpayer_id,
    }).encode()
    req = urllib.request.Request(
        CHECKER_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())

if __name__ == "__main__":
    print(check_pin("12345678", individual=True))
```

For production, cache the token (e.g. in a helper or Redis) and reuse until close to expiry.

---

### PHP

```php
<?php
$baseUrl = getenv('KRA_BASE_URL') ?: 'https://api.kra.go.ke';
$tokenUrl = getenv('KRA_TOKEN_URL') ?: $baseUrl . '/oauth/token';
$checkerUrl = getenv('KRA_CHECKER_URL') ?: $baseUrl . '/checker/v1/pin';

function getKraToken(): string {
    $key = getenv('KRA_CLIENT_ID');
    $secret = getenv('KRA_CLIENT_SECRET');
    $auth = base64_encode("$key:$secret");
    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => [
                "Authorization: Basic $auth",
                'Content-Type: application/x-www-form-urlencoded',
            ],
            'content' => 'grant_type=client_credentials',
        ],
    ]);
    $res = file_get_contents(getenv('KRA_TOKEN_URL') ?: (getenv('KRA_BASE_URL') ?: 'https://api.kra.go.ke') . '/oauth/token', false, $ctx);
    if ($res === false) throw new \RuntimeException('Token request failed');
    $data = json_decode($res, true);
    return $data['access_token'];
}

function checkKraPin(string $taxpayerId, bool $individual = true): array {
    $token = getKraToken();
    $body = json_encode([
        'TaxpayerType' => $individual ? 'KE' : 'COMP',
        'TaxpayerID' => $taxpayerId,
    ]);
    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => [
                "Authorization: Bearer $token",
                'Content-Type: application/json',
            ],
            'content' => $body,
        ],
    ]);
    $res = file_get_contents(getenv('KRA_CHECKER_URL') ?: (getenv('KRA_BASE_URL') ?: 'https://api.kra.go.ke') . '/checker/v1/pin', false, $ctx);
    if ($res === false) throw new \RuntimeException('Checker request failed');
    return json_decode($res, true);
}

$result = checkKraPin('12345678', true);
print_r($result);
```

Set `KRA_CLIENT_ID` and `KRA_CLIENT_SECRET` in your environment or server config.

---

### Go

```go
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getToken() (string, error) {
	baseURL := getenv("KRA_BASE_URL", "https://api.kra.go.ke")
	tokenURL := getenv("KRA_TOKEN_URL", baseURL+"/oauth/token")
	key := os.Getenv("KRA_CLIENT_ID")
	secret := os.Getenv("KRA_CLIENT_SECRET")
	auth := base64.StdEncoding.EncodeToString([]byte(key + ":" + secret))

	req, _ := http.NewRequest("POST", tokenURL, bytes.NewReader([]byte("grant_type=client_credentials")))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token: %d", resp.StatusCode)
	}
	var data struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.AccessToken, nil
}

func checkPin(taxpayerID string, individual bool) (map[string]interface{}, error) {
	baseURL := getenv("KRA_BASE_URL", "https://api.kra.go.ke")
	checkerURL := getenv("KRA_CHECKER_URL", baseURL+"/checker/v1/pin")
	token, err := getToken()
	if err != nil {
		return nil, err
	}

	taxpayerType := "KE"
	if !individual {
		taxpayerType = "COMP"
	}
	body, _ := json.Marshal(map[string]string{
		"TaxpayerType": taxpayerType,
		"TaxpayerID":   taxpayerID,
	})

	req, _ := http.NewRequest("POST", checkerURL, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checker: %d %s", resp.StatusCode, string(b))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func main() {
	result, err := checkPin("12345678", true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%+v\n", result)
}
```

Run with `KRA_CLIENT_ID` and `KRA_CLIENT_SECRET` set. For production, cache the token and reuse until a few minutes before expiry.

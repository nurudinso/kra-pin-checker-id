/**
 * KRA PIN Checker server – serves the HTML page and /check API.
 * Credentials stay in .env on the server.
 *
 * Usage: node server.js
 * Then open http://localhost:3000
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

// Load .env (strip inline # comments from values)
try {
  const envPath = path.join(__dirname, '.env');
  fs.readFileSync(envPath, 'utf8').split('\n').forEach((line) => {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (m && process.env[m[1]] === undefined) {
      const val = m[2].replace(/\s*#.*$/, '').replace(/^["']|["']$/g, '').trim();
      process.env[m[1]] = val;
    }
  });
} catch (_) {}

// Production GavaConnect: https://api.kra.go.ke
const baseUrl = (process.env.KRA_BASE_URL || 'https://api.kra.go.ke').replace(/\/$/, '');
const clientId = process.env.KRA_CLIENT_ID;
const clientSecret = process.env.KRA_CLIENT_SECRET;

const TOKEN_CACHE_MS = 55 * 60 * 1000; // 55 minutes
let cachedToken = null;
let tokenExpiry = 0;

async function getToken() {
  if (cachedToken && Date.now() < tokenExpiry) return cachedToken;

  const credentials = Buffer.from(`${clientId}:${clientSecret}`, 'utf8').toString('base64');
  const headers = {
    Authorization: `Basic ${credentials}`,
    Accept: 'application/json',
  };

  // Try KRA_TOKEN_URL first, then /oauth/token, then /v1/token/generate (sandbox-style)
  const urlsToTry = [];
  if (process.env.KRA_TOKEN_URL) {
    urlsToTry.push({ url: process.env.KRA_TOKEN_URL.trim(), method: 'POST', body: 'grant_type=client_credentials', contentType: 'application/x-www-form-urlencoded' });
  }
  urlsToTry.push(
    { url: `${baseUrl}/oauth/token`, method: 'POST', body: 'grant_type=client_credentials', contentType: 'application/x-www-form-urlencoded' },
    { url: `${baseUrl}/v1/token/generate?grant_type=client_credentials`, method: 'POST', body: 'grant_type=client_credentials', contentType: 'application/x-www-form-urlencoded' },
    { url: `${baseUrl}/v1/token/generate?grant_type=client_credentials`, method: 'GET', body: null, contentType: null },
  );

  let lastStatus = 0;
  let lastBody = '';

  for (const { url, method, body, contentType } of urlsToTry) {
    const reqHeaders = { ...headers };
    if (contentType) reqHeaders['Content-Type'] = contentType;
    const res = await fetch(url, {
      method,
      headers: reqHeaders,
      body: body || undefined,
    });
    const resBody = await res.text();
    lastStatus = res.status;
    lastBody = resBody;

    if (res.ok) {
      let data;
      try {
        data = JSON.parse(resBody);
      } catch (_) {
        continue;
      }
      if (data.access_token) {
        cachedToken = data.access_token;
        tokenExpiry = Date.now() + TOKEN_CACHE_MS;
        return cachedToken;
      }
    }
    if (res.status !== 404) break; // stop on 401/400, only try next on 404
  }

  let errMsg = lastBody || `HTTP ${lastStatus}`;
  try {
    const j = JSON.parse(lastBody);
    errMsg = j.errorMessage || j.error_message || j.message || errMsg;
  } catch (_) {}
  console.error('Token failed', lastStatus, lastBody || '(empty body)');
  throw new Error(`Token failed ${lastStatus}: ${errMsg}`);
}

async function pinChecker(accessToken, taxpayerId, taxpayerType) {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };

  const checkerUrl = process.env.KRA_CHECKER_URL?.trim();
  const isCheckerV1Pin = checkerUrl?.includes('/checker/v1/pin') || !checkerUrl;

  // /checker/v1/pin expects { TaxpayerType: "KE"|"COMP"|..., TaxpayerID }
  const bodyV1Pin = JSON.stringify({
    TaxpayerType: taxpayerType === 'NONINDIVIDUAL' ? 'COMP' : 'KE',
    TaxpayerID: String(taxpayerId),
  });
  // GavaConnect style: { taxpayerID, taxpayerType: "INDIVIDUAL"|"NONINDIVIDUAL" }
  const bodyGava = JSON.stringify({
    taxpayerID: String(taxpayerId),
    taxpayerType: taxpayerType === 'NONINDIVIDUAL' ? 'NONINDIVIDUAL' : 'INDIVIDUAL',
  });

  const urlsToTry = [];
  if (checkerUrl) {
    urlsToTry.push({ url: checkerUrl, body: isCheckerV1Pin ? bodyV1Pin : bodyGava });
  }
  const pinUrl = `${baseUrl}/checker/v1/pin`;
  if (!urlsToTry.some((x) => x.url === pinUrl)) urlsToTry.push({ url: pinUrl, body: bodyV1Pin });
  const gavaUrl = `${baseUrl}/gavaconnect/pinchecker/v1/check`;
  if (!urlsToTry.some((x) => x.url === gavaUrl)) urlsToTry.push({ url: gavaUrl, body: bodyGava });

  let lastRes = null;
  let lastBody = '';

  for (const { url, body } of urlsToTry) {
    const res = await fetch(url, { method: 'POST', headers, body });
    const text = await res.text();
    lastRes = res;
    lastBody = text;
    if (res.ok) {
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
      return { status: res.status, ok: true, data };
    }
    if (res.status !== 404) break;
  }

  let data;
  try {
    data = JSON.parse(lastBody);
  } catch {
    data = lastBody;
  }
  return { status: lastRes?.status ?? 404, ok: false, data };
}

const PORT = Number(process.env.PORT) || 3000;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const method = req.method || 'GET';
  console.log(method, url.pathname);

  if (url.pathname === '/' && method === 'GET') {
    const file = path.join(__dirname, 'index.html');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(fs.readFileSync(file, 'utf8'));
    return;
  }

  if (url.pathname === '/check' && req.method === 'POST') {
    let body = '';
    for await (const chunk of req) body += chunk;
    let taxpayerId, taxpayerType;
    try {
      const json = JSON.parse(body || '{}');
      taxpayerId = json.taxpayerId ?? json.taxpayerID ?? json.id;
      taxpayerType = json.taxpayerType ?? json.taxpayer_type ?? 'INDIVIDUAL';
    } catch (_) {
      taxpayerId = null;
    }
    if (!taxpayerId) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Missing taxpayer ID (taxpayerId or id)' }));
      return;
    }
    if (!clientId || !clientSecret) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Server: KRA_CLIENT_ID / KRA_CLIENT_SECRET not set' }));
      return;
    }
    try {
      const token = await getToken();
      const result = await pinChecker(token, taxpayerId, taxpayerType);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: result.ok, status: result.status, data: result.data }));
    } catch (err) {
      const detail = err.cause ? (err.cause.message || err.cause.code || String(err.cause)) : '';
      console.error('KRA request failed:', err.message, detail || '');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: false,
        error: err.message,
        detail: detail || (err.code || ''),
      }));
    }
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log('');
  console.log('  KRA PIN Checker server is running');
  console.log('  Open in your browser:  http://localhost:' + PORT);
  console.log('');
});

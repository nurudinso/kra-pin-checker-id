#!/usr/bin/env node
/**
 * KRA PIN Checker (Production GavaConnect):
 * 1. POST /oauth/token with Basic auth -> access_token
 * 2. POST /gavaconnect/pinchecker/v1/check with { taxpayerID, taxpayerType }
 *
 * Usage:
 *   node run-kra-pin-checker.js [TaxpayerID] [INDIVIDUAL|NONINDIVIDUAL]
 *   KRA_CLIENT_ID=xxx KRA_CLIENT_SECRET=xxx node run-kra-pin-checker.js 12345678 INDIVIDUAL
 *
 * Env: KRA_BASE_URL (default https://api.kra.go.ke), KRA_CLIENT_ID, KRA_CLIENT_SECRET
 */

// Load .env
try {
  require('fs').readFileSync('.env', 'utf8').split('\n').forEach((line) => {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/\s*#.*$/, '').replace(/^["']|["']$/g, '').trim();
  });
} catch (_) {}

const baseUrl = (process.env.KRA_BASE_URL || 'https://api.kra.go.ke').replace(/\/$/, '');
const clientId = process.env.KRA_CLIENT_ID;
const clientSecret = process.env.KRA_CLIENT_SECRET;
const taxpayerId = process.argv[2] || process.env.TAXPAYER_ID || '12345678';
const taxpayerType = (process.argv[3] || process.env.TAXPAYER_TYPE || 'INDIVIDUAL').toUpperCase() === 'NONINDIVIDUAL' ? 'NONINDIVIDUAL' : 'INDIVIDUAL';

async function getToken() {
  const url = `${baseUrl}/oauth/token`;
  const credentials = Buffer.from(`${clientId}:${clientSecret}`, 'utf8').toString('base64');
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: 'grant_type=client_credentials',
  });
  if (!res.ok) throw new Error(`Token failed ${res.status}: ${await res.text()}`);
  const data = await res.json();
  if (!data.access_token) throw new Error('No access_token in response');
  return data.access_token;
}

async function pinChecker(accessToken, taxpayerId, taxpayerType) {
  const url = `${baseUrl}/gavaconnect/pinchecker/v1/check`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ taxpayerID: String(taxpayerId), taxpayerType }),
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  return { status: res.status, ok: res.ok, data };
}

async function main() {
  if (!clientId || !clientSecret) {
    console.error('Missing credentials. Set KRA_CLIENT_ID and KRA_CLIENT_SECRET.');
    console.error('Example: KRA_CLIENT_ID=your_id KRA_CLIENT_SECRET=your_secret node run-kra-pin-checker.js 1000000');
    process.exit(1);
  }

  console.log('KRA PIN Checker (Production GavaConnect)');
  console.log('  Base URL:     ', baseUrl);
  console.log('  TaxpayerID:   ', taxpayerId);
  console.log('  TaxpayerType: ', taxpayerType);
  console.log('');

  try {
    console.log('1. GetToken...');
    const token = await getToken();
    console.log('   OK (access_token received)\n');

    console.log('2. PIN Checker...');
    const { status, ok, data } = await pinChecker(token, taxpayerId, taxpayerType);
    console.log('   HTTP', status);
    console.log('   Response:', typeof data === 'object' ? JSON.stringify(data, null, 2) : data);
    console.log('');
    if (ok && data && (data.pin || data.status === 'SUCCESS')) {
      console.log('Done.');
      if (data.pin) console.log('  PIN:', data.pin);
      if (data.taxpayerName) console.log('  Name:', data.taxpayerName);
    } else {
      process.exit(1);
    }
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

main();

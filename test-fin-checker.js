#!/usr/bin/env node
/**
 * Test script for KRA "FIN Checker by PIN" API
 * POST /api/fin-checker with body: { "pin": "<national-id>" }
 *
 * Usage:
 *   node test-fin-checker.js [PIN]
 *   KRA_API_BASE_URL=https://your-api.com node test-fin-checker.js 20180909-001
 */

const baseUrl = process.env.KRA_API_BASE_URL || 'https://api.example.com';
const pin = process.argv[2] || '20180909-001';

async function testFinChecker() {
  const url = `${baseUrl.replace(/\/$/, '')}/api/fin-checker`;
  console.log('Testing FIN Checker by PIN');
  console.log('  URL:', url);
  console.log('  PIN:', pin);
  console.log('');

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ pin }),
    });

    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }

    console.log('HTTP Status:', res.status, res.statusText);
    console.log('Response:', typeof data === 'object' ? JSON.stringify(data, null, 2) : data);
    console.log('');

    if (res.ok) {
      console.log('✓ Request succeeded');
      if (data?.data?.found) {
        console.log('  FIN:', data.data.fin, '| Status:', data.data.status);
      }
    } else {
      console.log('✗ Request failed');
      if (data?.message) console.log('  Message:', data.message);
      if (data?.errors?.length) data.errors.forEach((e) => console.log('  -', e.field + ':', e.message));
    }
  } catch (err) {
    console.error('Request failed:', err.message);
    process.exit(1);
  }
}

testFinChecker();

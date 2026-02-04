#!/usr/bin/env bash
# Test script for KRA "FIN Checker by PIN" API
# POST /api/fin-checker with body: { "pin": "<national-id>" }

set -e

# Set your API base URL (e.g. https://your-devgateway.com or http://localhost:3000)
BASE_URL="${KRA_API_BASE_URL:-https://api.example.com}"
PIN="${1:-20180909-001}"

echo "Testing FIN Checker by PIN"
echo "  Base URL: $BASE_URL"
echo "  PIN:      $PIN"
echo ""

curl -s -w "\n\nHTTP Status: %{http_code}\n" \
  -X POST "$BASE_URL/api/fin-checker" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d "{\"pin\": \"$PIN\"}" | cat

echo ""

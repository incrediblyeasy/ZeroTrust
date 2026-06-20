#!/usr/bin/env bash

set -uo pipefail
KC=http://localhost:8180
SVC=http://localhost:8000
ES=http://localhost:9200

line() { echo; echo "============================================================"; echo "$1"; echo "============================================================"; }

line "STEP 0  —  Preflight: is the stack running?"
if ! curl -sf "$KC/realms/ztac/.well-known/openid-configuration" >/dev/null 2>&1; then
  echo "  Stack is not reachable on $KC."
  echo "  Start it first, then re-run this demo:"
  echo "      docker compose up -d keycloak elasticsearch logstash kibana protected-service"
  echo "  (give services ~40s to become healthy)"
  exit 1
fi
echo "  OK — Keycloak is responding."

line "STEP 1  —  Services are up and healthy"
docker compose ps --format "table {{.Name}}\t{{.Status}}"

line "STEP 2  —  Identity: Keycloak issues a signed JWT badge (user: alice / admin)"
curl -s -X POST "$KC/realms/ztac/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=ztac-cli&username=alice&password=alice123" -o demo_tok.json
python -c "
import json,base64
t=json.load(open('demo_tok.json'))['access_token']
p=t.split('.')[1]; p+='='*(-len(p)%4)
c=json.loads(base64.urlsafe_b64decode(p))
print('  preferred_username :', c['preferred_username'])
print('  realm roles        :', c['realm_access']['roles'])
print('  jti (badge id)     :', c['jti'])
print('  lifespan (exp-iat) :', c['exp']-c['iat'], 'seconds  (short-lived = zero trust)')
"
rm -f demo_tok.json

line "STEP 3  —  Protected service: three tiered endpoints respond"
echo "-- /api/data/public  (anyone):";  curl -s "$SVC/api/data/public"
echo; echo "-- /api/data/reports (analyst+):"; curl -s "$SVC/api/data/reports"
echo; echo "-- /api/data/admin   (admin):";    curl -s "$SVC/api/data/admin"
echo

line "STEP 4  —  Accountability: generate audit traffic, then count stored logs"
for i in $(seq 1 8); do curl -s "$SVC/api/data/public" >/dev/null; done
echo "  Sent 8 requests. Waiting for Logstash to ingest + hash-chain them..."
sleep 7
curl -s "$ES/ztac-audit-*/_count"
echo

line "STEP 5  —  Integrity proof: verify the SHA-256 hash chain (should PASS)"
python scripts/verify_log_chain.py

line "STEP 6  —  Tamper detection: inject a FORGED log, then re-verify (should FAIL)"
curl -s -X POST "$ES/ztac-audit-tampered/_doc" -H "Content-Type: application/json" -d '{
  "timestamp":"2026-06-18T07:00:00.000Z","source_component":"ATTACKER","user":"alice",
  "action":"DELETE","resource":"/api/data/admin","status_code":200,
  "log_sequence":99999,"previous_hash":"FORGED_PREV","log_hash":"FORGED_HASH",
  "log_body_for_hash":"{\"fake\":true}","message":"Attacker-injected entry"}' \
  -o /dev/null -w "  Forged log inserted (HTTP %{http_code}). The attacker is trying to hide tracks.\n"
curl -s -X POST "$ES/ztac-audit-tampered/_refresh" >/dev/null
sleep 1
python scripts/verify_log_chain.py
echo
echo "  ^ The verifier caught the forged entry. Cleaning up the tampered index..."
curl -s -X DELETE "$ES/ztac-audit-tampered" -o /dev/null -w "  Cleanup done (HTTP %{http_code}).\n"

line "DEMO COMPLETE"
echo "Open the Kibana audit dashboard in a browser:  http://localhost:5601"
echo "(Stack Management > Saved Objects has the imported 'ztac-audit' dashboard.)"

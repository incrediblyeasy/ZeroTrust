# ZTAC Framework — Evaluation Report

## 1. Test environment

- Host: [your machine specs]
- Docker Engine: [version]
- Keycloak: 24.0.4
- OPA: 0.68.x
- Envoy: 1.31.x
- Elasticsearch: 8.14.1
- Python: 3.12

## 2. Adversarial scenario results

### Scenario 1: Token replay

- **Procedure:** Obtained valid JWT for user `bob` (analyst). Verified access
  to `/api/data/reports` (200). Revoked all sessions via Keycloak Admin API.
  Replayed the same token.
- **Expected:** 401 Unauthorized
- **Actual:** [fill in]
- **CyBOK principle validated:** Session Management, Non-repudiation
- **Evidence:** [paste ELK log snippet showing the rejected request]

### Scenario 2: Privilege escalation
[Person B fills this in]

### Scenario 3: Unauthenticated service-to-service call
[Person B fills this in]

### Scenario 4: Stale session exploitation

- **Procedure:** Obtained valid JWT for user `alice` (admin). Waited for token
  to expire (5 minutes). Attempted access with expired token.
- **Expected:** 401 Unauthorized
- **Actual:** [fill in]
- **CyBOK principle validated:** Continuous Verification, Session Management
- **Evidence:** [paste OPA decision log showing expiry-based denial]

### Scenario 5: Log tampering detection

- **Procedure:** Generated 3 legitimate access logs. Verified hash chain
  integrity using `verify_log_chain.py`. Injected a fake log entry directly
  into Elasticsearch. Re-ran hash chain verification.
- **Expected:** Verification fails, reports broken chain at the injected entry.
- **Actual:** [fill in]
- **CyBOK principle validated:** Audit Log Integrity, Non-repudiation
- **Evidence:** [paste verifier output showing the detected break]

## 3. Performance benchmark

### Methodology
Used `hey` (HTTP load generator) to measure request latency through the
full chain at three concurrency levels.

### Commands
```bash
# Install hey
go install github.com/rakyll/hey@latest

# Get a valid token
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztac/protocol/openid-connect/token \
  -d "grant_type=password&client_id=ztac-cli&username=bob&password=bob123" | jq -r .access_token)

# 10 concurrent connections, 200 total requests
hey -n 200 -c 10 -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/data/reports

# 50 concurrent
hey -n 500 -c 50 -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/data/reports

# 100 concurrent
hey -n 1000 -c 100 -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/data/reports
```

### Results

| Concurrency | Total requests | Avg latency | P99 latency | Requests/sec | Error rate |
|---|---|---|---|---|---|
| 10 | 200 | [fill in] | [fill in] | [fill in] | [fill in] |
| 50 | 500 | [fill in] | [fill in] | [fill in] | [fill in] |
| 100 | 1000 | [fill in] | [fill in] | [fill in] | [fill in] |

### Analysis
[Discuss the overhead introduced by ext_authz. Compare latency with and
without OPA in the request path. Note any bottlenecks.]

## 4. Summary

[Overall assessment of the framework's effectiveness against the five
adversarial scenarios, the CyBOK alignment coverage, and practical
deployment considerations.]

# OPA server authorization policy (enabled via `--authorization=basic`).
#
# Without this, OPA's management API is open: anyone able to reach :8181 on the
# docker network could PUT /v1/policies or PATCH /v1/data and rewrite the
# authorization rules — a full policy-tamper / authz-bypass. This restricts the
# API surface to exactly what the gateway needs: evaluate the decision and probe
# health. Every other endpoint (policy push, data writes, bundle ops) is denied.
package system.authz

import rego.v1

default allow := false

# The gateway's per-request authorization decision query.
allow if {
	input.method == "POST"
	input.path == ["v1", "data", "authz", "allow"]
}

# Liveness probing (docker healthcheck + gateway /verify dependency check).
allow if {
	input.method == "GET"
	input.path == ["health"]
}

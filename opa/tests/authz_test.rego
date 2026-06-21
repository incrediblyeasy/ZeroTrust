package authz_test

import rego.v1

import data.authz

future_exp := 9999999999

past_exp := 1000000000

test_allow_public_no_auth if {
	authz.allow with input as {
		"user": "anonymous",
		"roles": [],
		"action": "GET",
		"resource": "/api/data/public",
		"token_exp": 0,
		"token_jti": "",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

test_allow_analyst_reports if {
	authz.allow with input as {
		"user": "bob",
		"roles": ["analyst"],
		"action": "GET",
		"resource": "/api/data/reports",
		"token_exp": future_exp,
		"token_jti": "jti-bob",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

test_allow_admin_reports if {
	authz.allow with input as {
		"user": "alice",
		"roles": ["admin"],
		"action": "GET",
		"resource": "/api/data/reports",
		"token_exp": future_exp,
		"token_jti": "jti-alice",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

test_allow_admin_admin_endpoint if {
	authz.allow with input as {
		"user": "alice",
		"roles": ["admin"],
		"action": "GET",
		"resource": "/api/data/admin",
		"token_exp": future_exp,
		"token_jti": "jti-alice",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

test_deny_viewer_reports if {
	not authz.allow with input as {
		"user": "charlie",
		"roles": ["viewer"],
		"action": "GET",
		"resource": "/api/data/reports",
		"token_exp": future_exp,
		"token_jti": "jti-charlie",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

test_deny_viewer_admin if {
	not authz.allow with input as {
		"user": "charlie",
		"roles": ["viewer"],
		"action": "GET",
		"resource": "/api/data/admin",
		"token_exp": future_exp,
		"token_jti": "jti-charlie",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

test_deny_analyst_admin if {
	not authz.allow with input as {
		"user": "bob",
		"roles": ["analyst"],
		"action": "GET",
		"resource": "/api/data/admin",
		"token_exp": future_exp,
		"token_jti": "jti-bob",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

test_deny_expired_token if {
	not authz.allow with input as {
		"user": "alice",
		"roles": ["admin"],
		"action": "GET",
		"resource": "/api/data/admin",
		"token_exp": past_exp,
		"token_jti": "jti-alice",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

test_deny_high_risk_ip if {
	not authz.allow with input as {
		"user": "alice",
		"roles": ["admin"],
		"action": "GET",
		"resource": "/api/data/admin",
		"token_exp": future_exp,
		"token_jti": "jti-alice",
		"device_trust": "managed",
		"ip_risk": "high",
	}
}

test_deny_untrusted_device if {
	not authz.allow with input as {
		"user": "alice",
		"roles": ["admin"],
		"action": "GET",
		"resource": "/api/data/admin",
		"token_exp": future_exp,
		"token_jti": "jti-alice",
		"device_trust": "untrusted",
		"ip_risk": "low",
	}
}

test_deny_no_roles if {
	not authz.allow with input as {
		"user": "nobody",
		"roles": [],
		"action": "GET",
		"resource": "/api/data/reports",
		"token_exp": future_exp,
		"token_jti": "jti-none",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

test_deny_missing_role_claim if {
	not authz.allow with input as {
		"user": "nobody",
		"action": "GET",
		"resource": "/api/data/reports",
		"token_exp": future_exp,
		"token_jti": "jti-none",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

test_allow_byod_compliant_device if {
	authz.allow with input as {
		"user": "bob",
		"roles": ["analyst"],
		"action": "GET",
		"resource": "/api/data/reports",
		"token_exp": future_exp,
		"token_jti": "jti-bob",
		"device_trust": "byod_compliant",
		"ip_risk": "low",
	}
}

# Unknown resource paths are explicitly denied.
test_deny_unknown_resource if {
	not authz.allow with input as {
		"user": "alice",
		"roles": ["admin"],
		"action": "GET",
		"resource": "/api/data/secret-stuff",
		"token_exp": future_exp,
		"token_jti": "jti-alice",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

# Deny reason is "unknown_resource" for unregistered paths.
test_deny_reason_unknown_resource if {
	authz.deny_reason == "unknown_resource" with input as {
		"user": "alice",
		"roles": ["admin"],
		"action": "GET",
		"resource": "/not/registered",
		"token_exp": future_exp,
		"token_jti": "jti-alice",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

# Deny reason is "insufficient_role" when the path is known but the role is not.
test_deny_reason_insufficient_role if {
	authz.deny_reason == "insufficient_role" with input as {
		"user": "charlie",
		"roles": ["viewer"],
		"action": "GET",
		"resource": "/api/data/admin",
		"token_exp": future_exp,
		"token_jti": "jti-charlie",
		"device_trust": "managed",
		"ip_risk": "low",
	}
}

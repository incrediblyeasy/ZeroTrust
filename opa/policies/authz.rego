package authz

import rego.v1

import data.blocked_ip_risk_levels
import data.resource_roles
import data.trusted_device_levels

default allow := false

# The requested resource must be registered. Unknown paths are denied
# intentionally, not by relying on undefined lookups evaluating to false.
resource_known if {
	resource_roles[input.resource]
}

# Public access only when the resource is explicitly flagged public — an empty
# required_roles list alone is no longer sufficient, so a newly added resource
# is never world-readable by accident.
allow if {
	resource_known
	resource_roles[input.resource].required_roles == []
	resource_roles[input.resource].public == true
}

allow if {
	resource_known
	token_valid
	role_sufficient
	device_trusted
	ip_safe
}

token_valid if {
	input.token_exp > time.now_ns() / 1000000000
}

role_sufficient if {
	some role in input.roles
	role in resource_roles[input.resource].required_roles
}

device_trusted if {
	input.device_trust in trusted_device_levels
}

ip_safe if {
	not input.ip_risk in blocked_ip_risk_levels
}

# Structured deny reasons for diagnostics and audit.
deny_reason := "unknown_resource" if {
	not resource_known
}

deny_reason := "expired_token" if {
	resource_known
	not token_valid
}

deny_reason := "insufficient_role" if {
	resource_known
	token_valid
	not role_sufficient
}

deny_reason := "untrusted_device" if {
	resource_known
	token_valid
	role_sufficient
	not device_trusted
}

deny_reason := "blocked_ip" if {
	resource_known
	token_valid
	role_sufficient
	device_trusted
	not ip_safe
}

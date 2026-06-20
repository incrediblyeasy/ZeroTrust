package authz

import rego.v1

import data.blocked_ip_risk_levels
import data.resource_roles
import data.trusted_device_levels

default allow := false

allow if {
	resource_roles[input.resource].required_roles == []
}

allow if {
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

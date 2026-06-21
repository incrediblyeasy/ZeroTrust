package rbac

import rego.v1

import data.resource_roles

default allow := false

allow if {
	resource_roles[input.resource]
	some role in input.roles
	role in resource_roles[input.resource].required_roles
}

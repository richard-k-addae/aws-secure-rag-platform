package terraform.security

import rego.v1

required_tags := {"Project", "Environment", "ManagedBy"}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.mode == "managed"
	tags := object.get(resource.change.after, "tags_all", {})
	missing := required_tags - {k | tags[k]}
	count(missing) > 0
	msg := sprintf("%s: missing required tags %v", [resource.address, missing])
}

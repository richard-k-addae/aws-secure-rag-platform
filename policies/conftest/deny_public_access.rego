package terraform.security

import rego.v1

# Deny resources that expose the platform publicly.
# Run against a terraform plan JSON: conftest test tfplan.json -p policies/conftest

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_db_instance"
	resource.change.after.publicly_accessible == true
	msg := sprintf("%s: RDS instances must not be publicly accessible", [resource.address])
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_public_access_block"
	resource.change.after.block_public_acls == false
	msg := sprintf("%s: S3 public ACLs must be blocked", [resource.address])
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_ecs_service"
	resource.change.after.network_configuration[_].assign_public_ip == true
	msg := sprintf("%s: ECS tasks must not have public IPs", [resource.address])
}

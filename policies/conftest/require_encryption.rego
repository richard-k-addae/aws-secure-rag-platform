package terraform.security

import rego.v1

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_db_instance"
	resource.change.after.storage_encrypted != true
	msg := sprintf("%s: RDS storage must be encrypted", [resource.address])
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
	rule := resource.change.after.rule[_]
	not rule.apply_server_side_encryption_by_default
	msg := sprintf("%s: S3 buckets must define default encryption", [resource.address])
}

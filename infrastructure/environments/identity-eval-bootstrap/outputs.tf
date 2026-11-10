# Role ARNs only, for the operator's local AWS CLI profiles. Not sensitive.
output "terraform_role_arn" {
  value = aws_iam_role.terraform.arn
}

output "harness_role_arn" {
  value = aws_iam_role.harness.arn
}

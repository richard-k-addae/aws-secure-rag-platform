# Identifiers only. A public client has no secret; nothing here is sensitive.
output "user_pool_id" {
  value = aws_cognito_user_pool.eval.id
}

output "oidc_issuer" {
  value = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.eval.id}"
}

output "jwks_uri" {
  value = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.eval.id}/.well-known/jwks.json"
}

output "app_client_id" {
  value = aws_cognito_user_pool_client.app.id
}

output "other_client_id" {
  value = aws_cognito_user_pool_client.other.id
}

output "group_names" {
  value = sort([for g in aws_cognito_user_group.eval : g.name])
}

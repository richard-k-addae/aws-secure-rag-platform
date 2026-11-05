# M8 identity configuration warning.
#
# A `check` block produces a WARNING in plan/apply output; it does not stop a
# plan or apply and is not a deployment gate. The deployment gate is
# documented in docs/runbooks/DEPLOYMENT_RUNBOOK.md and
# docs/security/M8_IDENTITY_EVIDENCE.md.
#
# With either value empty the application fails closed: every protected route
# answers 503 "Authentication unavailable" while /healthz stays 200.
check "identity_configuration" {
  assert {
    condition     = var.oidc_issuer != "" && var.oidc_client_ids != ""
    error_message = "WARNING: OIDC_ISSUER and/or OIDC_CLIENT_IDS are empty. Protected API routes will fail closed with 503 until both are set to an approved production identity provider."
  }

  assert {
    condition     = var.oidc_issuer == "" || startswith(var.oidc_issuer, "https://cognito-idp.${var.aws_region}.amazonaws.com/${var.aws_region}_")
    error_message = "WARNING: oidc_issuer is not a Cognito user pool in the deployment region (${var.aws_region})."
  }
}

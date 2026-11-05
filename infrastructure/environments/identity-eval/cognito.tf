locals {
  name = "rag-identity-eval-m85"

  # Exactly the group names app/auth/tenancy.py maps. tenant-z is deliberately
  # NOT in TENANT_ALLOWLIST and exists only for the unknown-tenant case.
  groups = toset([
    "tenant:tenant-a",
    "tenant:tenant-b",
    "tenant:tenant-z",
    "role:reader",
    "role:ingestor",
    "role:admin",
  ])

  # Short-lived tokens bound the stale-group and no-revocation windows.
  client_settings = {
    explicit_auth_flows = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  }
}

resource "aws_cognito_user_pool" "eval" {
  name                = "${local.name}-pool"
  user_pool_tier      = "LITE"
  deletion_protection = "INACTIVE" # temporary stack: destroy must succeed
  mfa_configuration   = "OFF"      # synthetic users, admin-initiated auth only

  admin_create_user_config {
    allow_admin_create_user_only = true # no self sign-up
  }

  password_policy {
    minimum_length                   = 24
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 1
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }
}

resource "aws_cognito_user_group" "eval" {
  for_each     = local.groups
  name         = each.value
  user_pool_id = aws_cognito_user_pool.eval.id
  description  = "M8.5 synthetic evaluation group"
}

# The client the application allowlists (OIDC_CLIENT_IDS).
resource "aws_cognito_user_pool_client" "app" {
  name                                 = "${local.name}-app"
  user_pool_id                         = aws_cognito_user_pool.eval.id
  generate_secret                      = false
  explicit_auth_flows                  = local.client_settings.explicit_auth_flows
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  allowed_oauth_flows_user_pool_client = false
  auth_session_validity                = 3
  access_token_validity                = 5
  id_token_validity                    = 5
  refresh_token_validity               = 60

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "minutes"
  }
}

# Same pool and issuer, NOT allowlisted: proves client_id binding (AUTHN wrong_client).
resource "aws_cognito_user_pool_client" "other" {
  name                                 = "${local.name}-other"
  user_pool_id                         = aws_cognito_user_pool.eval.id
  generate_secret                      = false
  explicit_auth_flows                  = local.client_settings.explicit_auth_flows
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  allowed_oauth_flows_user_pool_client = false
  auth_session_validity                = 3
  access_token_validity                = 5
  id_token_validity                    = 5
  refresh_token_validity               = 60

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "minutes"
  }
}

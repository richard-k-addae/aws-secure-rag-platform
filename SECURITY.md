# Security Policy

## Scope

This is a portfolio reference implementation using synthetic data only. No production data, PHI, or real credentials are present in this repository or its deployed environments.

## Principles

- Least-privilege IAM for every component, scoped to specific actions and resources
- No long-lived cloud credentials in CI: CI currently has no AWS access (GitHub Actions OIDC is the target). Local operator access still uses a long-lived IAM user - a recorded residual risk
- Private networking by default: ECS tasks in private subnets, VPC endpoints for AWS services
- Encryption at rest (KMS) and in transit (TLS) for all data stores
- Secrets in AWS Secrets Manager; never in code, config files, or environment defaults
- Redacted logging by default: prompts and model responses are not logged outside a clearly labeled synthetic-data development mode
- Defense in depth for AI-specific risks: application-layer prompt boundaries, citation validation and sensitive-output withholding, verified by an independent adversarial test suite and bounded live evaluations. Bedrock Guardrails were evaluated and not adopted ([ADR 0005](docs/adr/0005-do-not-adopt-bedrock-guardrails.md)); no single control is treated as sufficient alone
- Known open items are listed in the [M7 evidence index](docs/security/M7_AI_SECURITY_EVIDENCE_INDEX.md) residual-risk register: verified identity (ID-01) is enforced in code since M8 but not yet verified against live Cognito or deployed ([M8 evidence](docs/security/M8_IDENTITY_EVIDENCE.md)); the sensitive-output detector gap remains open. The platform is not production-ready

## Reporting

If you find a vulnerability in this reference implementation, please open a GitHub issue or contact the maintainer directly. There is no bug bounty; this is an educational project.

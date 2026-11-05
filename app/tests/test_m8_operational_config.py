"""M8.6: operational configuration stays consistent with the verified-identity code.

Static checks over the Terraform source (no Terraform execution, no AWS):

* every security event a dashboard or alarm queries is one the application can
  actually emit, so a renamed or retired event (M6 ``missing_tenant``) cannot
  silently leave a widget empty again;
* the ECS task receives TENANT_ALLOWLIST, OIDC_ISSUER and OIDC_CLIENT_IDS from
  validated variables whose defaults fail closed, and no authentication-bypass
  setting exists.
"""

import re
from pathlib import Path

from app.core import telemetry

REPO = Path(__file__).resolve().parents[2]
DEV = REPO / "infrastructure" / "environments" / "dev"
ECS = REPO / "infrastructure" / "modules" / "ecs"
EVENT_PATTERN = re.compile(r'"rag\.security\.events",\s*"event",\s*"([a-z_]+)"')


def _tf(*paths: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in paths)


def test_dashboard_security_events_are_registered_events() -> None:
    events = set(EVENT_PATTERN.findall(_tf(DEV / "dashboard.tf")))
    assert events, "dashboard security widgets not found"
    assert events <= telemetry.SECURITY_EVENT_NAMES, events - telemetry.SECURITY_EVENT_NAMES
    assert {"missing_token", "identity_mapping_denied", "jwks_unavailable"} <= events
    assert "auth_not_configured" in events
    assert "missing_tenant" not in events


def test_alarm_security_event_dimensions_are_registered_events() -> None:
    alarms = _tf(DEV / "alarms.tf")
    events = set(re.findall(r'event\s*=\s*"([a-z_]+)"', alarms))
    assert events <= telemetry.SECURITY_EVENT_NAMES, events - telemetry.SECURITY_EVENT_NAMES


def test_ecs_task_receives_identity_configuration_from_variables() -> None:
    main = _tf(ECS / "main.tf")
    for name, variable in (
        ("TENANT_ALLOWLIST", "tenant_allowlist"),
        ("OIDC_ISSUER", "oidc_issuer"),
        ("OIDC_CLIENT_IDS", "oidc_client_ids"),
    ):
        assert f'{{ name = "{name}", value = var.{variable} }}' in main, name
    wiring = _tf(DEV / "main.tf")
    for variable in ("tenant_allowlist", "oidc_issuer", "oidc_client_ids"):
        assert re.search(rf"^\s*{variable}\s*=\s*var\.{variable}\s*$", wiring, re.M), variable


def test_identity_variables_are_validated_and_default_to_fail_closed() -> None:
    variables = _tf(ECS / "variables.tf")
    for variable, default in (
        ("oidc_issuer", '""'),
        ("oidc_client_ids", '""'),
        ("tenant_allowlist", '"tenant-a,tenant-b"'),
    ):
        block = re.search(rf'variable "{variable}" \{{(.*?)\n\}}', variables, re.S)
        assert block is not None, variable
        assert f"default     = {default}" in block.group(1), variable
        assert "validation {" in block.group(1), variable


def test_no_authentication_bypass_setting_exists() -> None:
    source = _tf(*ECS.glob("*.tf"), *DEV.glob("*.tf")).lower()
    for marker in ("auth_disabled", "disable_auth", "skip_auth", "auth_bypass", "x-tenant"):
        assert marker not in source, marker


def test_identity_warning_is_a_check_not_a_gate() -> None:
    identity = _tf(DEV / "identity.tf")
    assert 'check "identity_configuration"' in identity
    assert "not a deployment gate" in identity
    assert "precondition" not in identity and "postcondition" not in identity

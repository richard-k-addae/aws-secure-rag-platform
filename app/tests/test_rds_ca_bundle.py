"""The RDS CA bundle shipped in the image is exactly the reviewed AWS file.

`sslmode=verify-full` trusts whatever is in this file, so an edited or
swapped bundle would let a different server pass as the database. It is
public trust material, not a secret: the control here is integrity.

Source: https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem
To update it, replace the file with the new official bundle and change the
pinned digest in the same reviewed commit.
"""
import hashlib
from pathlib import Path

RDS_CA_BUNDLE = Path(__file__).resolve().parents[1] / "certs" / "rds-us-east-1-bundle.pem"
EXPECTED_SHA256 = "b1711d12bae51838581281e23b6cb97b1074016873b4dafc80ed14002462dd77"

# Where the Dockerfile's `COPY app/ ./app/` places it; database URLs use this
# as sslrootcert.
IMAGE_PATH = "/srv/app/certs/rds-us-east-1-bundle.pem"


def test_rds_ca_bundle_matches_pinned_digest() -> None:
    assert hashlib.sha256(RDS_CA_BUNDLE.read_bytes()).hexdigest() == EXPECTED_SHA256


def test_rds_ca_bundle_contains_only_certificates() -> None:
    text = RDS_CA_BUNDLE.read_text(encoding="ascii")
    assert text.count("-----BEGIN CERTIFICATE-----") == 3
    assert text.count("-----END CERTIFICATE-----") == 3
    assert "PRIVATE KEY" not in text


def test_rds_ca_bundle_sits_where_the_image_expects_it() -> None:
    repo_relative = RDS_CA_BUNDLE.relative_to(RDS_CA_BUNDLE.parents[2]).as_posix()
    assert repo_relative == IMAGE_PATH.removeprefix("/srv/")

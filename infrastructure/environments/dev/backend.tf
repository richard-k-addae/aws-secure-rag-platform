# Remote state: S3 with native locking (Terraform >= 1.10).
# Bucket is versioned, AES-256 encrypted, and public-access-blocked.
terraform {
  backend "s3" {
    bucket       = "rag-platform-tfstate-376129869231"
    key          = "dev/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

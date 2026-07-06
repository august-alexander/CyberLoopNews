# main (production) environment — COMMITTED, non-secret naming/config only.
#
# Loaded explicitly:
#   terraform workspace select main || terraform workspace new main
#   terraform apply -var-file=environments/main/terraform.tfvars
#
# Applies to the main workspace are gated behind the "main" GitHub Environment
# (required reviewers) — see .github/workflows/terraform-apply.yml.
#
# Secrets arrive as TF_VAR_* env vars from GitHub Secrets in CI.

environment = "main"

aws_region = "us-east-1"
project    = "cyberloopnews"

s3_bucket_name = "cyberloopnews-cve-data"
state_key      = "state/last_fetch.json"

schedule_expression = "cron(0 12 * * ? *)" # daily 12:00 UTC
lookback_hours      = 24

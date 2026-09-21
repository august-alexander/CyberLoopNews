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

s3_bucket_name     = "cyberloopnews-cve-data-main"
output_bucket_name = "cyberloopnews-cve-analysis-main"
state_key          = "state/last_fetch.json"

schedule_expression = "cron(0 * * * ? *)" # hourly at :00 — prod is the fresh one now
lookback_hours      = 24

# Prod's timers. They were held DISABLED until prod was seeded with dev's data
# (S3 sync + analyzer backfill, done 2026-09-21); set false to idle prod again
# without destroying anything.
schedules_enabled = true

# Prod serves the real domain, apex + www (dev is on dev.cyberloops.net).
dashboard_domain = "cyberloops.net"

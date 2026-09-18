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

# Everything that runs on a timer is created but DISABLED until prod has been
# seeded with dev's data (the S3 sync + analyzer backfill). Until then a live
# schedule would only accumulate CVEs that the sync overwrites, while spending
# Bedrock calls and NVD quota and mailing alerts about a half-built site.
# Flip to true once the seed is done and verified.
schedules_enabled = false

# dashboard_domain is deliberately UNSET until the cutover. CloudFront refuses
# the same alternate domain name on two distributions, so main cannot claim
# cyberloops.net until dev releases it. Prod runs on its *.cloudfront.net URL
# in the meantime.

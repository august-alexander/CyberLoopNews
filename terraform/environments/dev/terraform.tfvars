# dev environment — COMMITTED, non-secret naming/config only.
#
# Loaded explicitly (NOT auto-loaded, since it's not in the root dir):
#   terraform workspace select dev || terraform workspace new dev
#   terraform apply -var-file=environments/dev/terraform.tfvars
#
# Secrets (nist_api_key, alert_*, inbox_email) are NEVER here. Locally they come
# from the gitignored root terraform.tfvars (auto-loaded); in CI they arrive as
# TF_VAR_* env vars from GitHub Secrets.

environment = "dev"

aws_region = "us-east-1"
project    = "cyberloopnews"

# Referenced (not created) by the stack, so this bucket must already exist.
# Keep dev separate from prod so test runs never touch real customer data.
s3_bucket_name     = "cyberloopnews-cve-data-dev"
output_bucket_name = "cyberloopnews-cve-analysis-dev"
state_key          = "state/last_fetch.json"

schedule_expression = "cron(0 * * * ? *)" # hourly at :00 (small delta per fetch)
lookback_hours      = 24

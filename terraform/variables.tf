variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "Local AWS CLI profile to use for deployment."
  type        = string
  default     = "default"
}

variable "project" {
  description = "Project name, used as a prefix for resource names."
  type        = string
  default     = "cyberloopnews"
}

# Set per environment in environments/<env>.tfvars. Every resource name is
# prefixed with "${project}-${environment}", so dev and main never collide.
# Guarded below to always equal the active Terraform workspace.
variable "environment" {
  description = "Deployment environment; must match the git branch and Terraform workspace (e.g. dev, main)."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*$", var.environment))
    error_message = "environment must be lowercase alphanumeric/hyphens (e.g. dev, main, prodev, prod)."
  }
}

variable "s3_bucket_name" {
  description = "Existing S3 bucket for CVE data (referenced, not created)."
  type        = string
  default     = "cyberloopnews-cve-data"
}

variable "output_bucket_name" {
  description = "S3 bucket for per-CVE LoopScore analysis outputs. Created by this stack; set per environment (dev/main) so the branches never share a bucket."
  type        = string
  default     = "cyberloopnews-cve-analysis"
}

variable "bedrock_model_id" {
  description = "Bedrock model (inference profile) the analyzer uses to score CVEs."
  type        = string
  default     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "nist_api_key" {
  description = "NIST NVD API key."
  type        = string
  sensitive   = true
}

variable "nist_api_base_url" {
  description = "NVD 2.0 API endpoint."
  type        = string
  default     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
}

# Alerts are delivered by email only for now. Native SMS is deferred until a
# toll-free number is registered.
variable "inbox_email" {
  description = "Email inbox where alerts are delivered."
  type        = string
  sensitive   = true
}

variable "schedule_expression" {
  description = "EventBridge schedule for the fetcher. Default: daily at 12:00 UTC (8am ET during EDT)."
  type        = string
  default     = "cron(0 12 * * ? *)"
}

variable "edgar_schedule_expression" {
  description = "EventBridge schedule for the EDGAR fetcher. Default: daily at 12:05 UTC, between the CVE fetcher and the reporter."
  type        = string
  default     = "cron(5 12 * * ? *)"
}

variable "edgar_6k_schedule_expression" {
  description = "EventBridge schedule for the EDGAR 6-K fetcher. Default: daily at 12:10 UTC, between the 8-K fetcher and the reporter."
  type        = string
  default     = "cron(10 12 * * ? *)"
}

variable "report_schedule_expression" {
  description = "EventBridge schedule for the reporter. Default: daily at 12:15 UTC, 15 min after the fetcher."
  type        = string
  default     = "cron(15 12 * * ? *)"
}

variable "edgar_user_agent" {
  description = "User-Agent for SEC EDGAR requests. SEC requires a descriptive value with contact info or returns HTTP 403."
  type        = string
  default     = "CyberLoopNews aalexand@rednaxela.technology"
}

variable "edgar_lookback_days" {
  description = "How many days back the EDGAR fetcher searches for 8-K Item 1.05 filings on each run."
  type        = number
  default     = 1
}

variable "lookback_hours" {
  description = "On the first run (no state file), how far back to look."
  type        = number
  default     = 24
}

variable "state_key" {
  description = "S3 key for the last-fetch state file."
  type        = string
  default     = "state/last_fetch.json"
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds (pagination + S3 + SNS)."
  type        = number
  default     = 120
}

variable "lambda_memory" {
  description = "Lambda memory in MB."
  type        = number
  default     = 256
}

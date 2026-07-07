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

variable "report_schedule_expression" {
  description = "EventBridge schedule for the reporter. Default: daily at 12:15 UTC, 15 min after the fetcher."
  type        = string
  default     = "cron(15 12 * * ? *)"
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

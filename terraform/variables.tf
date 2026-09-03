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

# Custom domain the dashboard is served on. Set per environment in
# environments/<env>/terraform.tfvars. Empty (the default) = no custom domain,
# so the site is reached via the auto-assigned *.cloudfront.net URL. When set,
# Terraform provisions an ACM cert, its DNS validation, and the Route 53 alias
# records for the apex + www — all automatically (DNS is in Route 53).
variable "dashboard_domain" {
  description = "Apex custom domain for the dashboard (e.g. cyberloops.net). Empty = use the default *.cloudfront.net URL."
  type        = string
  default     = ""
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

variable "analysis_schedule_expression" {
  description = "EventBridge schedule for the analyzer. Default: hourly at :10, after the fetcher at :00."
  type        = string
  default     = "cron(10 * * * ? *)"
}

variable "analysis_timeout" {
  description = "Analyzer Lambda timeout in seconds. Batch mode makes one Bedrock call per CVE, so it needs longer than the fetchers."
  type        = number
  default     = 600
}

variable "analysis_max_per_run" {
  description = "Max CVEs the analyzer scores per invocation. Caps runtime/cost; leftovers score on the next run."
  type        = number
  default     = 50
}

variable "rescore_schedule_expression" {
  description = "EventBridge schedule for the analyzer's UNSCORED rescore sweep. Default: daily at 04:40 UTC, off the hourly pipeline's peak."
  type        = string
  default     = "cron(40 4 * * ? *)"
}

variable "rescore_lookback_days" {
  description = "How many days of NVD modifications the rescore sweep asks for. NVD caps this at 120; 7 gives a week of overlap so a missed run self-heals."
  type        = number
  default     = 7
}

variable "rescore_index_days" {
  description = "How far back the rescore sweep looks in our own table for UNSCORED rows. Wider than the NVD window, since a CVE published months ago can be analyzed today."
  type        = number
  default     = 180
}

variable "rescore_max_per_run" {
  description = "Max CVEs the rescore sweep scores per invocation. Rescoring reuses the stored model judgment, so this is a runtime bound, not a cost one."
  type        = number
  # Must stay above the number of CVEs that gain a CVSS in one lookback window.
  # At 300 the sweep capped out every single run, and anything it didn't reach
  # aged past the 7-day lastMod window before the next run — batch mode skips
  # those forever (they already have an analysis object), so a capped sweep
  # strands them as permanently UNSCORED. At 300 the run finished in 88s of a
  # 600s timeout, so the cap, not the clock, was the limit. This sets it high
  # enough that the handler's own wall-clock guard is what stops the loop.
  default = 2000
}

variable "ranking_schedule_expression" {
  description = "EventBridge Scheduler expression for the ranking alert. Default: 9am/1pm/5pm daily, evaluated in ranking_timezone."
  type        = string
  default     = "cron(0 9,13,17 * * ? *)"
}

variable "ranking_timezone" {
  description = "IANA timezone the ranking schedule is evaluated in. DST-aware, so the Eastern times hold year-round."
  type        = string
  default     = "America/New_York"
}

variable "ranking_top_n" {
  description = "How many top CVEs by LoopScore the ranking alert lists per send."
  type        = number
  default     = 10
}

variable "red_alert_threshold" {
  description = "LoopScore at/above which the red-alert Lambda emails immediately, one CVE at a time. High on purpose — raise it if alerts get too frequent."
  type        = number
  default     = 85
}

variable "dashboard_schedule_expression" {
  description = "EventBridge schedule for the dashboard data publisher. Default: hourly at :25, after the analyzer (:10) and enricher (:20) so it ranks fresh scores."
  type        = string
  default     = "cron(25 * * * ? *)"
}

variable "dashboard_max_n" {
  description = "How many CVEs each of the dashboard's timeframes carries. This is the largest top-N the page offers, so every setting of its 10/25/50 selector is a slice of data the browser already has."
  type        = number
  default     = 50
}

variable "dashboard_trend_days" {
  description = "Length of the per-day CVE count series behind the dashboard's sparkline."
  type        = number
  default     = 30
}

variable "dashboard_windows" {
  description = "Timeframes the dashboard publishes, in days (1 = today). Must match the timeframe buttons in web/index.html."
  type        = string
  default     = "1,7,30"
}

variable "broadcast_slots" {
  description = "The daily broadcast editions: slot name -> hour of day (evaluated in ranking_timezone). One EventBridge schedule is created per entry, each passing its own slot name to the Lambda so the show never has to guess which edition it is. The slot names must match SLOT_FRAMING in src/broadcast.py."
  type        = map(number)
  default = {
    morning = 9
    midday  = 13
  }
}

variable "broadcast_model_id" {
  description = "Bedrock model (inference profile) the broadcast writer uses. Deliberately a stronger model than bedrock_model_id: the analyzer makes ~1200 short scoring calls a day (Haiku is the right trade), while the broadcast is two calls a day whose entire output is prose. Note Sonnet 5 rejects sampling parameters — see the inferenceConfig note in src/broadcast.py before switching models."
  type        = string
  default     = "us.anthropic.claude-sonnet-5"
}

variable "broadcast_lookback_hours" {
  description = "How many hours of scored CVEs the broadcast writer draws on. Fixed window (unlike the ranking alert's delta) because the two slots are only four hours apart; the resulting overlap is handled in the script's framing, not the data."
  type        = number
  default     = 24
}

variable "broadcast_top_n" {
  description = "How many top CVEs by LoopScore go on the broadcast deck. Lower than ranking_top_n on purpose — a 4-5 minute read can only cover so many before it stops being a broadcast."
  type        = number
  default     = 8
}

# Search endpoint bounds (search_handler.py). These cap what a public visitor can
# ask the query Lambda for, so a filter request can't fan out into an expensive
# read of the CVE table.
variable "search_default_limit" {
  description = "Default page size for the search endpoint when the caller doesn't specify one."
  type        = number
  default     = 25
}

variable "search_max_limit" {
  description = "Hard cap on the search endpoint's page size, regardless of the requested limit."
  type        = number
  default     = 100
}

variable "search_default_days" {
  description = "Default recent-window size (days) for the search endpoint's browse mode when no vendor/CVE is given."
  type        = number
  default     = 7
}

variable "search_max_days" {
  description = "Hard cap on the search endpoint's recent-window size. Bounds the number of by_day Queries one request can make."
  type        = number
  default     = 30
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

variable "fetch_window_hours" {
  description = "Size of a single fetch window. Fixed per step so an outage can never grow the cost of one invocation."
  type        = number
  default     = 1
}

variable "max_windows_per_run" {
  description = "Max windows one fetcher invocation will advance. >1 lets a backlog drain without unbounding any single run."
  type        = number
  default     = 3
}

variable "enrich_schedule_expression" {
  description = "EventBridge schedule for the enricher. Default: hourly at :20, after the fetcher (:00) and analyzer (:10)."
  type        = string
  default     = "cron(20 * * * ? *)"
}

variable "enrich_timeout" {
  description = "Enricher Lambda timeout in seconds. It makes one CVE.org call per CVE, bounded internally by a wall-clock budget."
  type        = number
  default     = 600
}

variable "enrich_max_scans_per_run" {
  description = "Max raw scans (newest first) the enricher inspects per run."
  type        = number
  default     = 12
}

variable "enrich_reserve_seconds" {
  description = "Seconds of Lambda time the enricher holds back so partial progress is always written to S3."
  type        = number
  default     = 30
}

variable "state_key" {
  description = "S3 key for the last-fetch state file."
  type        = string
  default     = "state/last_fetch.json"
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds. Steady-state runs finish in seconds; the headroom is for the fetcher to clear a backlog window (NVD pagination + per-CVE enrichment, ~0.65s/CVE) in one catch-up run."
  type        = number
  default     = 200
}

variable "lambda_memory" {
  description = "Lambda memory in MB."
  type        = number
  default     = 256
}

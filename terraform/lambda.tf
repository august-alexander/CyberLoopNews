resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}-fetcher"
  retention_in_days = 14
  tags              = local.tags
}

resource "aws_lambda_function" "fetcher" {
  function_name = "${local.name_prefix}-fetcher"
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.12"
  handler       = "lambda_handler.lambda_handler"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      NIST_API_KEY        = var.nist_api_key
      NIST_API_BASE_URL   = var.nist_api_base_url
      S3_BUCKET           = var.s3_bucket_name
      STATE_KEY           = var.state_key
      LOOKBACK_HOURS      = var.lookback_hours
      FETCH_WINDOW_HOURS  = var.fetch_window_hours
      MAX_WINDOWS_PER_RUN = var.max_windows_per_run
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda,
    aws_cloudwatch_log_group.lambda,
  ]

  tags = local.tags
}

# Enricher: fills in CNA-supplied vendor/product data (from CVE.org) on the raw
# scans the fetcher wrote. Split out of the fetcher deliberately — see the module
# docstring in enrich_handler.py. Ships in the same zip; only the handler
# entrypoint differs. Reuses the fetcher IAM role: it needs exactly the same S3
# get/put/list on the data bucket, and no SNS.
resource "aws_cloudwatch_log_group" "enricher" {
  name              = "/aws/lambda/${local.name_prefix}-enricher"
  retention_in_days = 14
  tags              = local.tags
}

resource "aws_lambda_function" "enricher" {
  function_name = "${local.name_prefix}-enricher"
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.12"
  handler       = "enrich_handler.lambda_handler"
  timeout       = var.enrich_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      S3_BUCKET                = var.s3_bucket_name
      ENRICH_MAX_SCANS_PER_RUN = var.enrich_max_scans_per_run
      ENRICH_RESERVE_SECONDS   = var.enrich_reserve_seconds
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda,
    aws_cloudwatch_log_group.enricher,
  ]

  tags = local.tags
}

# EDGAR fetcher: pulls recent 8-K Item 1.05 (material cybersecurity incident)
# disclosures from SEC EDGAR and writes edgar/<ts>/filings.json to S3. Ships in
# the same zip; only the handler entrypoint differs. Reuses the fetcher IAM
# role — it already grants exactly the S3 get/put/list this needs.
resource "aws_cloudwatch_log_group" "edgar" {
  name              = "/aws/lambda/${local.name_prefix}-edgar-fetcher"
  retention_in_days = 14
  tags              = local.tags
}

resource "aws_lambda_function" "edgar_fetcher" {
  function_name = "${local.name_prefix}-edgar-fetcher"
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.12"
  handler       = "edgar_handler.lambda_handler"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      S3_BUCKET           = var.s3_bucket_name
      EDGAR_USER_AGENT    = var.edgar_user_agent
      EDGAR_LOOKBACK_DAYS = var.edgar_lookback_days
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda,
    aws_cloudwatch_log_group.edgar,
  ]

  tags = local.tags
}

# EDGAR 6-K fetcher: pulls recent 6-K cybersecurity incident disclosures (foreign
# private issuers) from SEC EDGAR and writes edgar6k/<ts>/filings.json to S3.
# Ships in the same zip; only the handler entrypoint differs. Reuses the fetcher
# IAM role — same S3 get/put/list, no SNS.
resource "aws_cloudwatch_log_group" "edgar_6k" {
  name              = "/aws/lambda/${local.name_prefix}-edgar-6k-fetcher"
  retention_in_days = 14
  tags              = local.tags
}

resource "aws_lambda_function" "edgar_6k_fetcher" {
  function_name = "${local.name_prefix}-edgar-6k-fetcher"
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.12"
  handler       = "edgar_6k_handler.lambda_handler"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      S3_BUCKET           = var.s3_bucket_name
      EDGAR_USER_AGENT    = var.edgar_user_agent
      EDGAR_LOOKBACK_DAYS = var.edgar_lookback_days
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda,
    aws_cloudwatch_log_group.edgar_6k,
  ]

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "reporter" {
  name              = "/aws/lambda/${local.name_prefix}-reporter"
  retention_in_days = 14
  tags              = local.tags
}

# Reporter: reads the latest raw/<ts>/cves.json the fetcher saved, builds a
# report, and emails it via SNS. Ships in the same zip as the fetcher; only the
# handler entrypoint differs.
resource "aws_lambda_function" "reporter" {
  function_name = "${local.name_prefix}-reporter"
  role          = aws_iam_role.reporter.arn
  runtime       = "python3.12"
  handler       = "report_handler.lambda_handler"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      S3_BUCKET     = var.s3_bucket_name
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [
    aws_iam_role_policy.reporter,
    aws_cloudwatch_log_group.reporter,
  ]

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "analyzer" {
  name              = "/aws/lambda/${local.name_prefix}-analyzer"
  retention_in_days = 14
  tags              = local.tags
}

# Analyzer: LoopScores CVEs (via Bedrock Converse) and writes the results to the
# analysis bucket. Ships in the same zip as the other Lambdas; only the handler
# entrypoint differs. Runs hourly via EventBridge (batch mode over the latest
# scan); also invokable manually with {"cve": …} or {"random": true}. Given a
# longer timeout than the fetchers since a batch run makes one Bedrock call per
# CVE.
resource "aws_lambda_function" "analyzer" {
  function_name = "${local.name_prefix}-analyzer"
  role          = aws_iam_role.analyzer.arn
  runtime       = "python3.12"
  handler       = "analysis_handler.lambda_handler"
  timeout       = var.analysis_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      S3_BUCKET            = var.s3_bucket_name        # source data bucket (raw scans)
      OUTPUT_BUCKET        = aws_s3_bucket.analysis.id # scored outputs land here
      BEDROCK_MODEL_ID     = var.bedrock_model_id
      ANALYSIS_MAX_PER_RUN = var.analysis_max_per_run
      CVE_TABLE            = aws_dynamodb_table.cves.name # queryable read-model
    }
  }

  depends_on = [
    aws_iam_role_policy.analyzer,
    aws_cloudwatch_log_group.analyzer,
  ]

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "red_alert" {
  name              = "/aws/lambda/${local.name_prefix}-red-alert"
  retention_in_days = 14
  tags              = local.tags
}

# Red alert: triggered by the analyzer's S3 write for each scored CVE (S3
# notification on the analysis bucket, see s3.tf). Reads that one scored object
# and, if its LoopScore is at/above the threshold, emails immediately via SNS.
# Ships in the same zip as the other Lambdas; only the handler entrypoint
# differs. No schedule — the per-CVE S3 event is the trigger.
resource "aws_lambda_function" "red_alert" {
  function_name = "${local.name_prefix}-red-alert"
  role          = aws_iam_role.red_alert.arn
  runtime       = "python3.12"
  handler       = "red_alert_handler.lambda_handler"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      OUTPUT_BUCKET       = aws_s3_bucket.analysis.id # scored results live here
      SNS_TOPIC_ARN       = aws_sns_topic.alerts.arn
      RED_ALERT_THRESHOLD = var.red_alert_threshold
    }
  }

  depends_on = [
    aws_iam_role_policy.red_alert,
    aws_cloudwatch_log_group.red_alert,
  ]

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "ranking" {
  name              = "/aws/lambda/${local.name_prefix}-ranking"
  retention_in_days = 14
  tags              = local.tags
}

# Ranking reporter: thrice-daily top-N LoopScore digest. Reads the scored
# results the analyzer wrote to the analysis bucket, ranks the CVEs scored since
# the last alert, and emails the digest via SNS. Ships in the same zip as the
# other Lambdas; only the handler entrypoint differs. Fired by EventBridge
# Scheduler at 9am/1pm/5pm ET (see scheduler.tf) so the times hold across DST.
resource "aws_lambda_function" "ranking" {
  function_name = "${local.name_prefix}-ranking"
  role          = aws_iam_role.ranking.arn
  runtime       = "python3.12"
  handler       = "ranking_handler.lambda_handler"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      OUTPUT_BUCKET     = aws_s3_bucket.analysis.id # scored results live here
      OUTPUT_PREFIX     = "analysis/"
      SNS_TOPIC_ARN     = aws_sns_topic.alerts.arn
      RANKING_TOP_N     = var.ranking_top_n
      RANKING_STATE_KEY = "ranking-state/last_alert.json"
    }
  }

  depends_on = [
    aws_iam_role_policy.ranking,
    aws_cloudwatch_log_group.ranking,
  ]

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "dashboard" {
  name              = "/aws/lambda/${local.name_prefix}-dashboard"
  retention_in_days = 14
  tags              = local.tags
}

# Dashboard publisher: ranks the top-N LoopScore CVEs over a fixed lookback and
# writes the static dashboard's summary JSON (data/top10.json) into the SITE
# bucket, same-origin with index.html. Ships in the same zip as the other
# Lambdas; only the handler entrypoint differs. Runs hourly via EventBridge (see
# eventbridge.tf), a few minutes after the analyzer so it ranks fresh scores.
resource "aws_lambda_function" "dashboard" {
  function_name = "${local.name_prefix}-dashboard"
  role          = aws_iam_role.dashboard.arn
  runtime       = "python3.12"
  handler       = "dashboard_handler.lambda_handler"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      OUTPUT_BUCKET            = aws_s3_bucket.analysis.id # scored results live here
      OUTPUT_PREFIX            = "analysis/"
      SITE_BUCKET              = aws_s3_bucket.site.id # the dashboard's JSON lands here
      DASHBOARD_KEY            = "data/top10.json"
      DASHBOARD_LOOKBACK_HOURS = var.dashboard_lookback_hours
      RANKING_TOP_N            = var.ranking_top_n
    }
  }

  depends_on = [
    aws_iam_role_policy.dashboard,
    aws_cloudwatch_log_group.dashboard,
  ]

  tags = local.tags
}

# Broadcast writer: merges the scored CVEs with the EDGAR breach filings and has
# Bedrock write a ready-to-read news script, emailed twice daily. Ships in the
# same zip as everything else; only the handler entrypoint differs. Gets the
# longer analyzer-style timeout because a full script is a single large Bedrock
# call, not the short scoring calls the other Lambdas make.
resource "aws_cloudwatch_log_group" "broadcast" {
  name              = "/aws/lambda/${local.name_prefix}-broadcast"
  retention_in_days = 14
  tags              = local.tags
}

resource "aws_lambda_function" "broadcast" {
  function_name = "${local.name_prefix}-broadcast"
  role          = aws_iam_role.broadcast.arn
  runtime       = "python3.12"
  handler       = "broadcast_handler.lambda_handler"
  timeout       = var.analysis_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      OUTPUT_BUCKET            = aws_s3_bucket.analysis.id # scored results live here
      OUTPUT_PREFIX            = "analysis/"
      S3_BUCKET                = var.s3_bucket_name # EDGAR dumps live here
      EDGAR_PREFIX             = "edgar/"
      EDGAR_6K_PREFIX          = "edgar6k/"
      SNS_TOPIC_ARN            = aws_sns_topic.alerts.arn
      BEDROCK_MODEL_ID         = var.bedrock_model_id
      BROADCAST_LOOKBACK_HOURS = var.broadcast_lookback_hours
      BROADCAST_TOP_N          = var.broadcast_top_n
    }
  }

  depends_on = [
    aws_iam_role_policy.broadcast,
    aws_cloudwatch_log_group.broadcast,
  ]

  tags = local.tags
}

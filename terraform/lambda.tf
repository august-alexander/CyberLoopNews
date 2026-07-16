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
      NIST_API_KEY      = var.nist_api_key
      NIST_API_BASE_URL = var.nist_api_base_url
      S3_BUCKET         = var.s3_bucket_name
      STATE_KEY         = var.state_key
      LOOKBACK_HOURS    = var.lookback_hours
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda,
    aws_cloudwatch_log_group.lambda,
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
    }
  }

  depends_on = [
    aws_iam_role_policy.analyzer,
    aws_cloudwatch_log_group.analyzer,
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

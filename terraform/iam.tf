data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.name_prefix}-fetcher-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "lambda_permissions" {
  # CloudWatch Logs
  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # Read/write raw dumps + state file (object-level actions target /*)
  statement {
    sid = "S3Objects"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = ["${data.aws_s3_bucket.cve_data.arn}/*"]
  }

  # ListBucket targets the bucket itself (no /*). Required so a GetObject on a
  # missing key (e.g. the state file on first run) returns NoSuchKey (404)
  # instead of AccessDenied (403).
  statement {
    sid       = "S3ListBucket"
    actions   = ["s3:ListBucket"]
    resources = [data.aws_s3_bucket.cve_data.arn]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${local.name_prefix}-fetcher-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

# ---------------------------------------------------------------------------
# Reporter role: read the raw dumps from S3 and publish the report to SNS.
# No PutObject — the reporter never writes to the bucket.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "reporter" {
  name               = "${local.name_prefix}-reporter-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "reporter_permissions" {
  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # Read the raw CVE dumps.
  statement {
    sid       = "S3Read"
    actions   = ["s3:GetObject"]
    resources = ["${data.aws_s3_bucket.cve_data.arn}/*"]
  }

  # List raw/ to find the most recent dump.
  statement {
    sid       = "S3ListBucket"
    actions   = ["s3:ListBucket"]
    resources = [data.aws_s3_bucket.cve_data.arn]
  }

  # Publish the report to our SNS topic (email).
  statement {
    sid       = "SNSPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "reporter" {
  name   = "${local.name_prefix}-reporter-policy"
  role   = aws_iam_role.reporter.id
  policy = data.aws_iam_policy_document.reporter_permissions.json
}

# ---------------------------------------------------------------------------
# Analyzer role: read the raw CVE dumps, invoke Bedrock to score each CVE, and
# write the scored results to the analysis output bucket.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "analyzer" {
  name               = "${local.name_prefix}-analyzer-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "analyzer_permissions" {
  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # Read the raw CVE dumps from the source data bucket.
  statement {
    sid       = "S3ReadRaw"
    actions   = ["s3:GetObject"]
    resources = ["${data.aws_s3_bucket.cve_data.arn}/*"]
  }

  statement {
    sid       = "S3ListRaw"
    actions   = ["s3:ListBucket"]
    resources = [data.aws_s3_bucket.cve_data.arn]
  }

  # Read + write scored results in the dedicated analysis output bucket.
  statement {
    sid = "S3Analysis"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.analysis.arn}/*"]
  }

  statement {
    sid       = "S3ListAnalysis"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.analysis.arn]
  }

  # Invoke Claude on Bedrock. Cross-region inference profiles (the "us.*" model
  # IDs) route to the foundation model in several regions, so both the
  # inference-profile ARN and the underlying foundation-model ARNs must be
  # allowed. Scoped to Anthropic models + this account's inference profiles.
  statement {
    sid     = "BedrockInvoke"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:*::foundation-model/anthropic.*",
      "arn:aws:bedrock:*:${data.aws_caller_identity.current.account_id}:inference-profile/*",
    ]
  }
}

resource "aws_iam_role_policy" "analyzer" {
  name   = "${local.name_prefix}-analyzer-policy"
  role   = aws_iam_role.analyzer.id
  policy = data.aws_iam_policy_document.analyzer_permissions.json
}

# ---------------------------------------------------------------------------
# Ranking reporter role: read the scored results from the analysis bucket, keep
# a small "last alert" marker there, and publish the digest to SNS. Deliberately
# narrower than the analyzer — no Bedrock, no access to the raw data bucket, and
# writes are scoped to just the ranking-state/ prefix.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "ranking" {
  name               = "${local.name_prefix}-ranking-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "ranking_permissions" {
  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # Read the per-CVE scored results.
  statement {
    sid       = "S3ReadAnalysis"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.analysis.arn}/*"]
  }

  # List analysis/ to find the objects scored since the last alert.
  statement {
    sid       = "S3ListAnalysis"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.analysis.arn]
  }

  # Persist the "last alert" marker — narrow write to the state prefix only.
  statement {
    sid       = "S3WriteMarker"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.analysis.arn}/ranking-state/*"]
  }

  # Publish the digest to our SNS topic (email).
  statement {
    sid       = "SNSPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "ranking" {
  name   = "${local.name_prefix}-ranking-policy"
  role   = aws_iam_role.ranking.id
  policy = data.aws_iam_policy_document.ranking_permissions.json
}

# ---------------------------------------------------------------------------
# Red-alert role: read a single scored result from the analysis bucket and
# publish to SNS. The narrowest role of them all — no Bedrock, no raw bucket, no
# writes (it keeps no state), no ListBucket (the S3 event hands it the key).
# ---------------------------------------------------------------------------
resource "aws_iam_role" "red_alert" {
  name               = "${local.name_prefix}-red-alert-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "red_alert_permissions" {
  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # Read the one scored result named in the triggering S3 event.
  statement {
    sid       = "S3ReadAnalysis"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.analysis.arn}/*"]
  }

  # Publish the alert to our SNS topic (email).
  statement {
    sid       = "SNSPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "red_alert" {
  name   = "${local.name_prefix}-red-alert-policy"
  role   = aws_iam_role.red_alert.id
  policy = data.aws_iam_policy_document.red_alert_permissions.json
}

# ---------------------------------------------------------------------------
# EventBridge Scheduler execution role: lets the ranking schedule invoke the
# ranking Lambda. Scheduler assumes this role (not a resource-based lambda
# permission like the cloudwatch_event_rule targets use).
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${local.name_prefix}-ranking-scheduler-role"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "scheduler_permissions" {
  statement {
    sid       = "InvokeRanking"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.ranking.arn]
  }
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "${local.name_prefix}-ranking-scheduler-policy"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler_permissions.json
}

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

  # Publish the alert to our SNS topic
  statement {
    sid       = "SNSPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${local.name_prefix}-fetcher-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

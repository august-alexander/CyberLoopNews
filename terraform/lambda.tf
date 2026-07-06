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
      SNS_TOPIC_ARN     = aws_sns_topic.alerts.arn
      LOOKBACK_HOURS    = var.lookback_hours
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda,
    aws_cloudwatch_log_group.lambda,
  ]

  tags = local.tags
}

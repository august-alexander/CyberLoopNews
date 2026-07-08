resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.name_prefix}-fetcher-schedule"
  description         = "Trigger the CVE fetcher on a schedule."
  schedule_expression = var.schedule_expression
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "${local.name_prefix}-fetcher"
  arn       = aws_lambda_function.fetcher.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fetcher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# EDGAR fetcher runs on its own schedule, between the CVE fetcher and the
# reporter, so both raw dumps are in S3 before the reporter reads them.
resource "aws_cloudwatch_event_rule" "edgar_schedule" {
  name                = "${local.name_prefix}-edgar-fetcher-schedule"
  description         = "Trigger the EDGAR 8-K 1.05 fetcher on a schedule."
  schedule_expression = var.edgar_schedule_expression
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "edgar" {
  rule      = aws_cloudwatch_event_rule.edgar_schedule.name
  target_id = "${local.name_prefix}-edgar-fetcher"
  arn       = aws_lambda_function.edgar_fetcher.arn
}

resource "aws_lambda_permission" "allow_eventbridge_edgar" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.edgar_fetcher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.edgar_schedule.arn
}

# Reporter runs on its own schedule, shortly after the fetcher, so the latest
# raw dump is already in S3 by the time it reads.
resource "aws_cloudwatch_event_rule" "report_schedule" {
  name                = "${local.name_prefix}-reporter-schedule"
  description         = "Trigger the CVE reporter on a schedule."
  schedule_expression = var.report_schedule_expression
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "reporter" {
  rule      = aws_cloudwatch_event_rule.report_schedule.name
  target_id = "${local.name_prefix}-reporter"
  arn       = aws_lambda_function.reporter.arn
}

resource "aws_lambda_permission" "allow_eventbridge_reporter" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reporter.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.report_schedule.arn
}

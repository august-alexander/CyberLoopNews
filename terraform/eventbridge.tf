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

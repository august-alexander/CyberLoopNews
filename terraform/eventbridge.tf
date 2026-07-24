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

# Enricher runs on its own schedule, offset from the fetcher so the newest raw
# scan is already in S3. It is intentionally NOT chained to the fetcher: if the
# enricher is failing (CVE.org down, slow, rate-limiting), ingest must keep
# running regardless. Independent schedules are what make that true.
resource "aws_cloudwatch_event_rule" "enrich_schedule" {
  name                = "${local.name_prefix}-enricher-schedule"
  description         = "Trigger the CVE.org vendor/product enricher on a schedule."
  schedule_expression = var.enrich_schedule_expression
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "enricher" {
  rule      = aws_cloudwatch_event_rule.enrich_schedule.name
  target_id = "${local.name_prefix}-enricher"
  arn       = aws_lambda_function.enricher.arn
}

resource "aws_lambda_permission" "allow_eventbridge_enricher" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enricher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.enrich_schedule.arn
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

# EDGAR 6-K fetcher runs on its own schedule, after the 8-K fetcher and before
# the reporter, so all dumps are in S3 before the reporter reads them.
resource "aws_cloudwatch_event_rule" "edgar_6k_schedule" {
  name                = "${local.name_prefix}-edgar-6k-fetcher-schedule"
  description         = "Trigger the EDGAR 6-K cyber-incident fetcher on a schedule."
  schedule_expression = var.edgar_6k_schedule_expression
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "edgar_6k" {
  rule      = aws_cloudwatch_event_rule.edgar_6k_schedule.name
  target_id = "${local.name_prefix}-edgar-6k-fetcher"
  arn       = aws_lambda_function.edgar_6k_fetcher.arn
}

resource "aws_lambda_permission" "allow_eventbridge_edgar_6k" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.edgar_6k_fetcher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.edgar_6k_schedule.arn
}

# Analyzer runs hourly, a few minutes after the fetcher, so the newest scan is
# already in S3. In batch mode it scores every not-yet-scored CVE in that scan
# and writes the results to the analysis bucket.
resource "aws_cloudwatch_event_rule" "analysis_schedule" {
  name                = "${local.name_prefix}-analyzer-schedule"
  description         = "Trigger the CVE analyzer on a schedule (batch mode)."
  schedule_expression = var.analysis_schedule_expression
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "analyzer" {
  rule      = aws_cloudwatch_event_rule.analysis_schedule.name
  target_id = "${local.name_prefix}-analyzer"
  arn       = aws_lambda_function.analyzer.arn
}

resource "aws_lambda_permission" "allow_eventbridge_analyzer" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.analyzer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.analysis_schedule.arn
}

# Dashboard publisher runs hourly, after the analyzer (:10) and enricher (:20),
# so it ranks the freshest scores when it rebuilds the site's top-N JSON.
resource "aws_cloudwatch_event_rule" "dashboard_schedule" {
  name                = "${local.name_prefix}-dashboard-schedule"
  description         = "Trigger the dashboard data publisher on a schedule."
  schedule_expression = var.dashboard_schedule_expression
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "dashboard" {
  rule      = aws_cloudwatch_event_rule.dashboard_schedule.name
  target_id = "${local.name_prefix}-dashboard"
  arn       = aws_lambda_function.dashboard.arn
}

resource "aws_lambda_permission" "allow_eventbridge_dashboard" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dashboard.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.dashboard_schedule.arn
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

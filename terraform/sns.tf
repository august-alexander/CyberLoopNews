resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-cve-alerts"
  tags = local.tags
}

# Email subscription to a real inbox. SNS sends a one-time "Confirm
# subscription" link that must be clicked before alerts flow. Email-only for
# now; native SMS is deferred until a toll-free number is registered.
resource "aws_sns_topic_subscription" "inbox" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.inbox_email
}

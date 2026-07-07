output "lambda_function_name" {
  description = "Name of the deployed fetcher Lambda."
  value       = aws_lambda_function.fetcher.function_name
}

output "reporter_function_name" {
  description = "Name of the deployed reporter Lambda."
  value       = aws_lambda_function.reporter.function_name
}

output "reporter_log_group" {
  description = "CloudWatch log group for the reporter Lambda."
  value       = aws_cloudwatch_log_group.reporter.name
}

output "sns_topic_arn" {
  description = "ARN of the CVE alerts SNS topic."
  value       = aws_sns_topic.alerts.arn
}

output "schedule_expression" {
  description = "Active EventBridge schedule."
  value       = aws_cloudwatch_event_rule.schedule.schedule_expression
}

output "log_group" {
  description = "CloudWatch log group for the Lambda."
  value       = aws_cloudwatch_log_group.lambda.name
}

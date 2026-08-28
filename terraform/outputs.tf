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

output "analyzer_function_name" {
  description = "Name of the deployed analyzer Lambda."
  value       = aws_lambda_function.analyzer.function_name
}

output "analyzer_log_group" {
  description = "CloudWatch log group for the analyzer Lambda."
  value       = aws_cloudwatch_log_group.analyzer.name
}

output "analysis_bucket" {
  description = "S3 bucket holding per-CVE LoopScore outputs."
  value       = aws_s3_bucket.analysis.id
}

output "ranking_function_name" {
  description = "Name of the deployed ranking-alert Lambda."
  value       = aws_lambda_function.ranking.function_name
}

output "ranking_log_group" {
  description = "CloudWatch log group for the ranking-alert Lambda."
  value       = aws_cloudwatch_log_group.ranking.name
}

output "dashboard_function_name" {
  description = "Name of the dashboard data-publisher Lambda (writes data/top10.json to the site bucket)."
  value       = aws_lambda_function.dashboard.function_name
}

output "search_function_name" {
  description = "Name of the search/query Lambda behind the site's filter panel."
  value       = aws_lambda_function.search.function_name
}

output "search_log_group" {
  description = "CloudWatch log group for the search Lambda."
  value       = aws_cloudwatch_log_group.search.name
}

output "search_endpoint" {
  description = "Same-origin search API (through CloudFront). Try: <url>?days=7 or ?vendor=cisco or ?cve=CVE-2026-1234."
  value       = "https://${aws_cloudfront_distribution.site.domain_name}/api/search"
}

output "schedule_expression" {
  description = "Active EventBridge schedule."
  value       = aws_cloudwatch_event_rule.schedule.schedule_expression
}

output "log_group" {
  description = "CloudWatch log group for the Lambda."
  value       = aws_cloudwatch_log_group.lambda.name
}

output "site_bucket" {
  description = "Private S3 bucket holding the static dashboard files."
  value       = aws_s3_bucket.site.id
}

output "dashboard_url" {
  description = "HTTPS URL of the CloudFront-hosted dashboard."
  value       = "https://${aws_cloudfront_distribution.site.domain_name}"
}

# After editing web/index.html and re-applying, the new file is in S3 but
# CloudFront may still serve the cached copy at the edge. Force a refresh with:
#   aws cloudfront create-invalidation --distribution-id <id> --paths "/*"
output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID (use for cache invalidations after a page edit)."
  value       = aws_cloudfront_distribution.site.id
}

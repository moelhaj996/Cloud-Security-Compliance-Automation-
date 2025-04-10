output "compliance_scanner_role_arn" {
  description = "ARN of the IAM role for compliance scanner"
  value       = aws_iam_role.compliance_scanner.arn
}

output "compliance_reports_bucket" {
  description = "Name of the S3 bucket storing compliance reports"
  value       = aws_s3_bucket.compliance_reports.id
}

output "compliance_alerts_topic_arn" {
  description = "ARN of the SNS topic for compliance alerts"
  value       = aws_sns_topic.compliance_alerts.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function running compliance scans"
  value       = aws_lambda_function.compliance_scanner.function_name
}

output "cloudwatch_log_group" {
  description = "Name of the CloudWatch Log Group for compliance scanner"
  value       = aws_cloudwatch_log_group.compliance_scanner.name
} 
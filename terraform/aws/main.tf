terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# IAM Role for the compliance scanner
resource "aws_iam_role" "compliance_scanner" {
  name = "compliance-scanner-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy for compliance scanning
resource "aws_iam_role_policy" "compliance_scanner" {
  name = "compliance-scanner-policy"
  role = aws_iam_role.compliance_scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:GetCredentialReport",
          "iam:GenerateCredentialReport",
          "iam:ListUsers",
          "iam:ListMFADevices",
          "iam:ListAccessKeys",
          "s3:ListAllMyBuckets",
          "s3:GetBucketEncryption",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketLogging",
          "config:GetResourceConfigHistory",
          "config:SelectResourceConfig"
        ]
        Resource = "*"
      }
    ]
  })
}

# S3 bucket for compliance reports
resource "aws_s3_bucket" "compliance_reports" {
  bucket = var.compliance_reports_bucket_name

  tags = {
    Name        = "Compliance Reports"
    Environment = var.environment
  }
}

# Enable bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "compliance_reports" {
  bucket = aws_s3_bucket.compliance_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "compliance_reports" {
  bucket = aws_s3_bucket.compliance_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable bucket versioning
resource "aws_s3_bucket_versioning" "compliance_reports" {
  bucket = aws_s3_bucket.compliance_reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable bucket logging
resource "aws_s3_bucket_logging" "compliance_reports" {
  bucket = aws_s3_bucket.compliance_reports.id

  target_bucket = aws_s3_bucket.compliance_reports.id
  target_prefix = "access-logs/"
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "compliance_scanner" {
  name              = "/aws/compliance-scanner"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    Application = "compliance-scanner"
  }
}

# SNS Topic for compliance alerts
resource "aws_sns_topic" "compliance_alerts" {
  name = "compliance-alerts"
}

# EventBridge rule for scheduled scanning
resource "aws_cloudwatch_event_rule" "compliance_scan" {
  name                = "compliance-scan-schedule"
  description         = "Trigger compliance scan on schedule"
  schedule_expression = var.scan_schedule

  tags = {
    Environment = var.environment
    Application = "compliance-scanner"
  }
}

# Lambda function for compliance scanning
resource "aws_lambda_function" "compliance_scanner" {
  filename         = "lambda_function.zip"
  function_name    = "compliance-scanner"
  role            = aws_iam_role.compliance_scanner.arn
  handler         = "main.lambda_handler"
  runtime         = "python3.9"
  timeout         = 300
  memory_size     = 512

  environment {
    variables = {
      REPORTS_BUCKET = aws_s3_bucket.compliance_reports.id
      ALERT_TOPIC    = aws_sns_topic.compliance_alerts.arn
      LOG_LEVEL      = "INFO"
    }
  }

  tags = {
    Environment = var.environment
    Application = "compliance-scanner"
  }
} 
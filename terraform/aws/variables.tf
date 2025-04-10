variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "compliance_reports_bucket_name" {
  description = "Name of the S3 bucket to store compliance reports"
  type        = string
}

variable "scan_schedule" {
  description = "Schedule expression for compliance scans (e.g., rate(1 hour))"
  type        = string
  default     = "rate(1 hour)"
} 
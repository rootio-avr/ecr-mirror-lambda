variable "aws_region" {
  type        = string
  description = "AWS region to deploy into."
  default     = "us-east-1"
}

variable "dst_repo" {
  type        = string
  description = "Base name for the ECR repository. Sub-repos will be created as <dst_repo>/<image_name>."
  default     = "root-mirror"
}

variable "lambda_image_uri" {
  type        = string
  description = "ECR image URI for the Lambda function (build and push the Dockerfile first)."
}

variable "root_registry_host" {
  type        = string
  description = "Root registry hostname."
  default     = "cr.root.io"
}

variable "webhook_signing_secret" {
  type        = string
  sensitive   = true
  description = "The signing secret provided by Root when creating the webhook subscription. Leave empty on the first apply; fill in after registering the webhook URL with Root."
  default     = ""
}

variable "root_api_key" {
  type        = string
  sensitive   = true
  description = "Root API key for authenticating pulls from cr.root.io."
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log group retention in days."
  default     = 14
}

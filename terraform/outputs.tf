output "webhook_url" {
  description = "Paste this URL into Root's webhook settings (POST /settings/webhooks)."
  value       = aws_lambda_function_url.mirror.function_url
}

output "ecr_repository_url" {
  description = "ECR repository URL where mirrored images will appear."
  value       = aws_ecr_repository.root_mirror.repository_url
}

output "log_group_name" {
  description = "CloudWatch log group name for the Lambda function."
  value       = aws_cloudwatch_log_group.lambda.name
}

output "lambda_function_name" {
  description = "Lambda function name."
  value       = aws_lambda_function.mirror.function_name
}

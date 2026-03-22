resource "aws_secretsmanager_secret" "webhook_secret" {
  name                    = "root-ecr-mirror/webhook-signing-secret"
  description             = "Root webhook HMAC signing secret for signature verification."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "webhook_secret" {
  count         = var.webhook_signing_secret != "" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.webhook_secret.id
  secret_string = var.webhook_signing_secret
}

resource "aws_secretsmanager_secret" "root_api_key" {
  name                    = "root-ecr-mirror/root-api-key"
  description             = "Root API key for pulling images from cr.root.io."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "root_api_key" {
  secret_id     = aws_secretsmanager_secret.root_api_key.id
  secret_string = var.root_api_key
}

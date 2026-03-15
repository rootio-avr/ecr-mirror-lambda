data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda_permissions" {
  statement {
    sid    = "ECRPush"
    effect = "Allow"
    actions = [
      "ecr:CreateRepository",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:DescribeRepositories",
      "ecr:BatchGetImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
    ]
    resources = [
      aws_ecr_repository.root_mirror.arn,
      "${aws_ecr_repository.root_mirror.arn}/*",
    ]
  }

  statement {
    sid       = "ECRAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "SecretsRead"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [
      aws_secretsmanager_secret.webhook_secret.arn,
      aws_secretsmanager_secret.root_api_key.arn,
    ]
  }
}

data "aws_iam_policy" "lambda_basic" {
  name = "AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "lambda" {
  name                = "root-ecr-mirror"
  assume_role_policy  = data.aws_iam_policy_document.lambda_assume.json
  managed_policy_arns = [data.aws_iam_policy.lambda_basic.arn]
}

resource "aws_iam_role_policy" "lambda" {
  name   = "ecr-push-and-secrets"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/root-ecr-mirror"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "mirror" {
  function_name = "root-ecr-mirror"
  role          = aws_iam_role.lambda.arn
  package_type  = "Image"
  image_uri     = var.lambda_image_uri
  timeout       = 600
  memory_size   = 1024

  environment {
    variables = {
      WEBHOOK_SECRET_ARN = aws_secretsmanager_secret.webhook_secret.arn
      ROOT_API_KEY_ARN   = aws_secretsmanager_secret.root_api_key.arn
      DST_REPO_URL       = aws_ecr_repository.root_mirror.repository_url
      ROOT_REGISTRY_HOST = var.root_registry_host
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda,
  ]
}

resource "aws_lambda_function_url" "mirror" {
  function_name      = aws_lambda_function.mirror.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "public_url_invoke" {
  statement_id           = "AllowPublicURLInvoke"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.mirror.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "public_function_invoke" {
  statement_id  = "AllowPublicFunctionInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.mirror.function_name
  principal     = "*"
}

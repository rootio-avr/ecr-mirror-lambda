resource "aws_dynamodb_table" "mirror_locks" {
  name         = "${local.name}-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "key"

  attribute {
    name = "key"
    type = "S"
  }
}

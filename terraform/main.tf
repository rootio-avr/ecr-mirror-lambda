provider "aws" {
  region = var.aws_region
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  suffix = var.name_suffix != "" ? "-${var.name_suffix}" : ""
  name   = "root-ecr-mirror${local.suffix}"
}

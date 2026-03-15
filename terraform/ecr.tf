resource "aws_ecr_repository" "root_mirror" {
  name                 = var.dst_repo
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

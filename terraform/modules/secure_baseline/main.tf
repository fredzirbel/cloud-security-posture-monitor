##############################################################################
# CIS-compliant reference configuration for comparison
##############################################################################

variable "region" {
  type    = string
  default = "us-east-1"
}

# --- S3: Properly secured bucket ---

resource "aws_s3_bucket" "secure" {
  bucket        = "cspm-demo-secure-bucket"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# --- Security Group: Restrictive rules ---

resource "aws_vpc" "secure" {
  cidr_block = "10.1.0.0/16"
  tags       = { Name = "cspm-demo-secure-vpc" }
}

resource "aws_security_group" "secure" {
  name        = "cspm-demo-restricted-sg"
  description = "Properly restricted security group"
  vpc_id      = aws_vpc.secure.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.1.0.0/16"]
    description = "SSH from VPC only"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound"
  }

  tags = { Name = "cspm-demo-restricted-sg" }
}

##############################################################################
# Intentionally misconfigured AWS resources for CSPM scanning demonstration
# DO NOT deploy this in a real AWS account.
##############################################################################

variable "region" {
  type    = string
  default = "us-east-1"
}

# --- S3: Public bucket, no encryption, no versioning, no logging ---

resource "aws_s3_bucket" "vulnerable" {
  bucket        = "cspm-demo-vulnerable-bucket"
  force_destroy = true
}

# No public access block = FAIL on s3-public-access-block
# No encryption config   = FAIL on s3-default-encryption
# No versioning          = FAIL on s3-versioning
# No logging             = FAIL on s3-access-logging

# --- Security Group: SSH and RDP open to the world ---

resource "aws_vpc" "demo" {
  cidr_block = "10.0.0.0/16"
  tags       = { Name = "cspm-demo-vpc" }
}

resource "aws_security_group" "vulnerable" {
  name        = "cspm-demo-open-sg"
  description = "Intentionally overly permissive security group"
  vpc_id      = aws_vpc.demo.id

  # SSH open to world = FAIL on sg-unrestricted-ssh
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH open to world (intentionally insecure)"
  }

  # RDP open to world = FAIL on sg-unrestricted-rdp
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP open to world (intentionally insecure)"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cspm-demo-open-sg" }
}

# --- IAM: Wildcard admin policy ---

resource "aws_iam_user" "vulnerable" {
  name = "cspm-demo-vulnerable-user"
}

resource "aws_iam_policy" "admin_wildcard" {
  name        = "cspm-demo-admin-wildcard"
  description = "Intentionally overly permissive policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "vulnerable" {
  user       = aws_iam_user.vulnerable.name
  policy_arn = aws_iam_policy.admin_wildcard.arn
}

# --- Outputs ---

output "bucket_name" {
  value = aws_s3_bucket.vulnerable.bucket
}

output "sg_id" {
  value = aws_security_group.vulnerable.id
}

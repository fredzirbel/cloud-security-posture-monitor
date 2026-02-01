terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region

  # LocalStack overrides for local testing
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  dynamic "endpoints" {
    for_each = var.use_localstack ? [1] : []
    content {
      s3         = var.localstack_endpoint
      iam        = var.localstack_endpoint
      ec2        = var.localstack_endpoint
      rds        = var.localstack_endpoint
      cloudtrail = var.localstack_endpoint
      sts        = var.localstack_endpoint
    }
  }
}

module "vulnerable" {
  source = "./modules/vulnerable"
  region = var.region
}

module "secure_baseline" {
  source = "./modules/secure_baseline"
  region = var.region
  count  = var.deploy_secure_baseline ? 1 : 0
}

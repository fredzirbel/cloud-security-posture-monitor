variable "region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

variable "use_localstack" {
  description = "Set to true when using LocalStack for local testing"
  type        = bool
  default     = true
}

variable "localstack_endpoint" {
  description = "LocalStack endpoint URL"
  type        = string
  default     = "http://localhost:4566"
}

variable "deploy_secure_baseline" {
  description = "Deploy the secure baseline resources alongside the vulnerable ones"
  type        = bool
  default     = false
}

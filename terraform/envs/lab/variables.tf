variable "account_id" {
  description = "The lab AWS account ID. The provider refuses to run against any other account."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "The single region the lab runs in."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Prefix for resource names."
  type        = string
  default     = "detlab"
}

variable "enable_workload" {
  description = "Deploy the VPC and EC2 instance that generate flow-log traffic."
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub as the findings aggregator."
  type        = bool
  default     = true
}

variable "protected_iam_users" {
  description = "IAM users the auto-responders will alert on but never quarantine (put your admin user here)."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "Days to keep CloudTrail and flow logs in S3."
  type        = number
  default     = 90
}

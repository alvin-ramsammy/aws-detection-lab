variable "account_id" {
  description = "The lab AWS account ID. The provider refuses to run against any other account."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "The lab region (for regional defaults like EBS encryption)."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  type    = string
  default = "detlab"
}

variable "alert_email" {
  description = "Email address for budget and billing alarm notifications."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly budget; alerts fire at 50/75/100% actual and 100% forecasted."
  type        = number
  default     = 10
}

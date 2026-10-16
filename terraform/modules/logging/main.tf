variable "name" {
  type = string
}

variable "log_retention_days" {
  type = number
}

variable "enable_flow_logs" {
  type = bool
}

variable "flow_log_vpc_id" {
  type    = string
  default = null
}

variable "enable_security_hub" {
  type = bool
}

variable "queries_dir" {
  description = "Directory of saved Athena queries (*.sql, templated with $${database})."
  type        = string
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  trail_name = "${var.name}-trail"
  trail_arn  = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}

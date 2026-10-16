terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws.us_east_1]
    }
  }
}

variable "name" {
  type = string
}

variable "alert_email" {
  type = string
}

variable "monthly_budget_usd" {
  type = number
}

# --- Account-wide safe defaults ------------------------------------------------

resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# New instances in this region get IMDSv2-only by default. IMDSv1 is how SSRF
# bugs turn into stolen instance credentials (the Capital One breach pattern).
resource "aws_ec2_instance_metadata_defaults" "this" {
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
}

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 16
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
}

# --- Billing guardrails -------------------------------------------------------

resource "aws_sns_topic" "billing" {
  provider = aws.us_east_1
  name     = "${var.name}-billing-alerts"
}

resource "aws_sns_topic_subscription" "billing_email" {
  provider  = aws.us_east_1
  topic_arn = aws_sns_topic.billing.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Alerts the moment anything bills at all.
resource "aws_budgets_budget" "zero_spend" {
  name         = "${var.name}-zero-spend"
  budget_type  = "COST"
  limit_amount = "0.01"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = [50, 75, 100]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.alert_email]
    }
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}

# Independent second tripwire. Requires "Receive Billing Alerts" to be on in
# Billing preferences (done in Phase 1).
resource "aws_cloudwatch_metric_alarm" "billing" {
  provider            = aws.us_east_1
  alarm_name          = "${var.name}-estimated-charges"
  alarm_description   = "Estimated charges exceeded the monthly budget."
  namespace           = "AWS/Billing"
  metric_name         = "EstimatedCharges"
  dimensions          = { Currency = "USD" }
  statistic           = "Maximum"
  period              = 21600
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.monthly_budget_usd
  alarm_actions       = [aws_sns_topic.billing.arn]
}

# --- Slack webhook for detection alerts ---------------------------------------
# Lives in the permanent baseline so it survives lab destroy/apply cycles.
# Terraform creates it with a placeholder and never touches the value again,
# so the real webhook URL never appears in code or state. Set it with
# `make set-slack-webhook`.

resource "aws_ssm_parameter" "slack_webhook" {
  name        = "/${var.name}/slack-webhook-url"
  description = "Slack incoming webhook for detection alerts. Set out-of-band; see docs/deploy.md."
  type        = "SecureString"
  value       = "UNSET"

  lifecycle {
    ignore_changes = [value]
  }
}

output "slack_webhook_parameter" {
  value = aws_ssm_parameter.slack_webhook.name
}

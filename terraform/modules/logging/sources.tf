# --- CloudTrail ---------------------------------------------------------------
# Multi-region so activity in regions I never look at is still recorded; that's
# exactly where an attacker would spin up miners. A trail is also what makes
# "AWS API Call via CloudTrail" events reach EventBridge for Phase 4.

resource "aws_cloudtrail" "this" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.logs]
}

# --- VPC Flow Logs ------------------------------------------------------------

resource "aws_flow_log" "workload" {
  count = var.enable_flow_logs ? 1 : 0

  vpc_id                   = var.flow_log_vpc_id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${aws_s3_bucket.logs.arn}/vpc-flow-logs/"
  max_aggregation_interval = 60

  destination_options {
    file_format                = "plain-text"
    hive_compatible_partitions = false
    per_hour_partition         = false
  }

  depends_on = [aws_s3_bucket_policy.logs]
}

# --- GuardDuty ----------------------------------------------------------------
# Foundational detections (CloudTrail, VPC flow, DNS) plus S3 data events.
# The paid add-on protection plans are switched off explicitly to keep the
# bill predictable after the 30-day free trial.

resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "enabled" {
  for_each    = toset(["S3_DATA_EVENTS"])
  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "disabled" {
  for_each = toset([
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "LAMBDA_NETWORK_LOGS",
    "RUNTIME_MONITORING",
  ])
  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  status      = "DISABLED"
}

# --- Security Hub -------------------------------------------------------------
# Used as the single pane for GuardDuty findings. Compliance standards are off
# by default: they need AWS Config recording, which has its own per-item cost.

resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0

  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
}

output "trail_name" {
  value = aws_cloudtrail.this.name
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.this.id
}

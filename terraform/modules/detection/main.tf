variable "name" {
  type = string
}

variable "rules_dir" {
  description = "Directory of detection definitions (detections/rules/*.json)."
  type        = string
}

variable "lambda_src_dir" {
  type = string
}

variable "protected_iam_users" {
  type = list(string)
}

variable "protected_buckets" {
  type = list(string)
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  arn_prefix = "arn:${data.aws_partition.current.partition}"

  # Created by envs/account. Referenced by name, never read, so the webhook
  # URL stays out of this state file.
  slack_param_name = "/${var.name}/slack-webhook-url"
  slack_param_arn  = "${local.arn_prefix}:ssm:${data.aws_region.current.region}:${local.account_id}:parameter${local.slack_param_name}"

  # Each detection is a JSON file: metadata + EventBridge pattern + which
  # responder handles it. Adding a detection = adding a file.
  rules = {
    for f in fileset(var.rules_dir, "*.json") :
    jsondecode(file("${var.rules_dir}/${f}")).name => jsondecode(file("${var.rules_dir}/${f}"))
  }

  # One least-privilege role per responder.
  responders = {
    notify = {
      statements = []
    }
    restore_logging = {
      statements = [{
        actions   = ["cloudtrail:StartLogging"]
        resources = ["${local.arn_prefix}:cloudtrail:*:${local.account_id}:trail/*"]
      }]
    }
    revoke_open_ingress = {
      statements = [
        {
          actions   = ["ec2:RevokeSecurityGroupIngress"]
          resources = ["${local.arn_prefix}:ec2:*:${local.account_id}:security-group/*"]
        },
        {
          actions   = ["ec2:DescribeSecurityGroups"]
          resources = ["*"]
        },
      ]
    }
    quarantine_iam_user = {
      statements = [
        {
          actions = [
            "iam:ListAccessKeys",
            "iam:UpdateAccessKey",
            "iam:DeleteLoginProfile",
            "iam:TagUser",
          ]
          resources = ["${local.arn_prefix}:iam::${local.account_id}:user/*"]
        },
        {
          # Can attach AWSDenyAll and nothing else — this role can't be used
          # to escalate privileges even if the function were compromised.
          actions   = ["iam:AttachUserPolicy"]
          resources = ["${local.arn_prefix}:iam::${local.account_id}:user/*"]
          condition = {
            test     = "ArnEquals"
            variable = "iam:PolicyARN"
            values   = ["${local.arn_prefix}:iam::aws:policy/AWSDenyAll"]
          }
        },
      ]
    }
    s3_policy_guard = {
      statements = [{
        actions   = ["s3:DeleteBucketPolicy"]
        resources = ["${local.arn_prefix}:s3:::*"]
      }]
    }
  }
}

# --- Lambda package and functions ---------------------------------------------

data "archive_file" "responders" {
  type        = "zip"
  source_dir  = var.lambda_src_dir
  output_path = "${path.root}/.build/responders.zip"
  excludes    = ["**/__pycache__/**"]
}

# All responders log to one group so Phase 5 validation can query a single place.
resource "aws_cloudwatch_log_group" "responders" {
  name              = "/${var.name}/responders"
  retention_in_days = 30
}

data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "responder" {
  for_each           = local.responders
  name               = "${var.name}-${replace(each.key, "_", "-")}"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

data "aws_iam_policy_document" "responder" {
  for_each = local.responders

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.responders.arn}:*"]
  }

  statement {
    sid       = "SlackWebhook"
    actions   = ["ssm:GetParameter"]
    resources = [local.slack_param_arn]
  }

  dynamic "statement" {
    for_each = each.value.statements
    content {
      actions   = statement.value.actions
      resources = statement.value.resources

      dynamic "condition" {
        for_each = lookup(statement.value, "condition", null) == null ? [] : [statement.value.condition]
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }
}

resource "aws_iam_role_policy" "responder" {
  for_each = local.responders
  name     = "responder"
  role     = aws_iam_role.responder[each.key].id
  policy   = data.aws_iam_policy_document.responder[each.key].json
}

resource "aws_lambda_function" "responder" {
  for_each = local.responders

  function_name    = "${var.name}-${replace(each.key, "_", "-")}"
  role             = aws_iam_role.responder[each.key].arn
  runtime          = "python3.13"
  handler          = "detlab.handlers.${each.key}.handler"
  filename         = data.archive_file.responders.output_path
  source_code_hash = data.archive_file.responders.output_base64sha256
  timeout          = 30
  memory_size      = 128

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.responders.name
  }

  environment {
    variables = {
      SLACK_WEBHOOK_PARAM = local.slack_param_name
      PROTECTED_IAM_USERS = join(",", var.protected_iam_users)
      PROTECTED_BUCKETS   = join(",", var.protected_buckets)
    }
  }

  depends_on = [aws_iam_role_policy.responder]
}

# --- EventBridge rules --------------------------------------------------------

resource "aws_cloudwatch_event_rule" "detection" {
  for_each = local.rules

  name          = "${var.name}-${each.value.id}-${each.key}"
  description   = "${each.value.id}: ${each.value.title}"
  event_pattern = jsonencode(each.value.event_pattern)
}

resource "aws_cloudwatch_event_target" "detection" {
  for_each = local.rules

  rule = aws_cloudwatch_event_rule.detection[each.key].name
  arn  = aws_lambda_function.responder[each.value.response].arn

  # Hand the responder the rule's metadata alongside the original event.
  input_transformer {
    input_template = "{\"detection\": ${jsonencode({ for k, v in each.value : k => v if k != "event_pattern" })}, \"event\": <aws.events.event.json>}"
  }

  retry_policy {
    maximum_retry_attempts       = 2
    maximum_event_age_in_seconds = 3600
  }
}

resource "aws_lambda_permission" "detection" {
  for_each = local.rules

  statement_id  = "eventbridge-${each.value.id}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder[each.value.response].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection[each.key].arn
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.responders.name
}

output "rule_names" {
  value = sort([for r in aws_cloudwatch_event_rule.detection : r.name])
}

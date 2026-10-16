output "slack_webhook_parameter" {
  description = "Run `make set-slack-webhook` to store the webhook URL here."
  value       = module.baseline.slack_webhook_parameter
}

module "baseline" {
  source = "../../modules/baseline"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  name               = var.name
  alert_email        = var.alert_email
  monthly_budget_usd = var.monthly_budget_usd
}

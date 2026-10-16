# The account baseline lives in envs/account (permanent). Everything here is
# safe to destroy between sessions.

# Phase 2 — something to protect and to generate network telemetry
module "workload" {
  source = "../../modules/workload"
  count  = var.enable_workload ? 1 : 0

  name = var.name
}

# Phase 3 — telemetry pipeline
module "logging" {
  source = "../../modules/logging"

  name                = var.name
  log_retention_days  = var.log_retention_days
  enable_flow_logs    = var.enable_workload
  flow_log_vpc_id     = var.enable_workload ? module.workload[0].vpc_id : null
  enable_security_hub = var.enable_security_hub
  queries_dir         = "${path.root}/../../../detections/queries"
}

# Phase 4 — detections and automated response
module "detection" {
  source = "../../modules/detection"

  name                = var.name
  rules_dir           = "${path.root}/../../../detections/rules"
  lambda_src_dir      = "${path.root}/../../../lambdas/src"
  protected_iam_users = var.protected_iam_users
  protected_buckets   = [module.logging.log_bucket_name, module.logging.athena_results_bucket_name]
}

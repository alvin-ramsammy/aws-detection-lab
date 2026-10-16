output "log_bucket" {
  value = module.logging.log_bucket_name
}

output "athena_workgroup" {
  value = module.logging.athena_workgroup
}

output "responder_log_group" {
  description = "Every detection that fires writes a DETECTION_FIRED line here."
  value       = module.detection.log_group_name
}

output "detection_rules" {
  value = module.detection.rule_names
}

output "workload_instance_id" {
  value = var.enable_workload ? module.workload[0].instance_id : null
}

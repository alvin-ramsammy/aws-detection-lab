# Athena instead of an always-on SIEM/OpenSearch cluster: pay per query,
# nothing running between sessions. Tables use partition projection, so there
# are no crawlers to run and no partitions to maintain.

locals {
  database = replace("${var.name}_logs", "-", "_")
}

data "aws_regions" "enabled" {}

resource "aws_s3_bucket" "athena_results" {
  bucket        = "${var.name}-athena-${local.account_id}-${local.region}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-results"
    status = "Enabled"
    filter {}

    expiration {
      days = 7
    }
  }
}

resource "aws_athena_workgroup" "this" {
  name          = var.name
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false

    # Cost guard: any single query scanning more than 1 GB is cancelled.
    bytes_scanned_cutoff_per_query = 1073741824

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}

resource "aws_glue_catalog_database" "this" {
  name = local.database
}

resource "aws_glue_catalog_table" "cloudtrail" {
  name          = "cloudtrail"
  database_name = aws_glue_catalog_database.this.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                        = "TRUE"
    "projection.enabled"            = "true"
    "projection.region.type"        = "enum"
    "projection.region.values"      = join(",", sort(data.aws_regions.enabled.names))
    "projection.date.type"          = "date"
    "projection.date.range"         = "2025/01/01,NOW"
    "projection.date.format"        = "yyyy/MM/dd"
    "projection.date.interval"      = "1"
    "projection.date.interval.unit" = "DAYS"
    "storage.location.template"     = "s3://${aws_s3_bucket.logs.bucket}/AWSLogs/${local.account_id}/CloudTrail/$${region}/$${date}"
  }

  partition_keys {
    name = "region"
    type = "string"
  }
  partition_keys {
    name = "date"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.logs.bucket}/AWSLogs/${local.account_id}/CloudTrail/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"
    }

    dynamic "columns" {
      for_each = [
        ["eventversion", "string"],
        ["useridentity", "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,onbehalfof:struct<userid:string,identitystorearn:string>,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>,sourceidentity:string,ec2roledelivery:string,ec2issuedinvpc:string>>"],
        ["eventtime", "string"],
        ["eventsource", "string"],
        ["eventname", "string"],
        ["awsregion", "string"],
        ["sourceipaddress", "string"],
        ["useragent", "string"],
        ["errorcode", "string"],
        ["errormessage", "string"],
        ["requestparameters", "string"],
        ["responseelements", "string"],
        ["additionaleventdata", "string"],
        ["requestid", "string"],
        ["eventid", "string"],
        ["readonly", "string"],
        ["resources", "array<struct<arn:string,accountid:string,type:string>>"],
        ["eventtype", "string"],
        ["apiversion", "string"],
        ["recipientaccountid", "string"],
        ["serviceeventdetails", "string"],
        ["sharedeventid", "string"],
        ["vpcendpointid", "string"],
        ["tlsdetails", "struct<tlsversion:string,ciphersuite:string,clienthostheader:string>"],
      ]
      content {
        name = columns.value[0]
        type = columns.value[1]
      }
    }
  }
}

resource "aws_glue_catalog_table" "vpc_flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name          = "vpc_flow_logs"
  database_name = aws_glue_catalog_database.this.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                        = "TRUE"
    "skip.header.line.count"        = "1"
    "projection.enabled"            = "true"
    "projection.date.type"          = "date"
    "projection.date.range"         = "2025/01/01,NOW"
    "projection.date.format"        = "yyyy/MM/dd"
    "projection.date.interval"      = "1"
    "projection.date.interval.unit" = "DAYS"
    "storage.location.template"     = "s3://${aws_s3_bucket.logs.bucket}/vpc-flow-logs/AWSLogs/${local.account_id}/vpcflowlogs/${local.region}/$${date}"
  }

  partition_keys {
    name = "date"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.logs.bucket}/vpc-flow-logs/AWSLogs/${local.account_id}/vpcflowlogs/${local.region}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
      parameters = {
        "field.delim"          = " "
        "serialization.format" = " "
      }
    }

    # Default (version 2) flow log format.
    dynamic "columns" {
      for_each = [
        ["version", "int"],
        ["account_id", "string"],
        ["interface_id", "string"],
        ["srcaddr", "string"],
        ["dstaddr", "string"],
        ["srcport", "int"],
        ["dstport", "int"],
        ["protocol", "bigint"],
        ["packets", "bigint"],
        ["bytes", "bigint"],
        ["start", "bigint"],
        ["end", "bigint"],
        ["action", "string"],
        ["log_status", "string"],
      ]
      content {
        name = columns.value[0]
        type = columns.value[1]
      }
    }
  }
}

# Hunting queries live in detections/queries/ and are loaded as saved queries.
resource "aws_athena_named_query" "this" {
  for_each = {
    for f in fileset(var.queries_dir, "*.sql") : trimsuffix(f, ".sql") => f
    if var.enable_flow_logs || !startswith(f, "flow_")
  }

  name      = "${var.name}-${each.key}"
  workgroup = aws_athena_workgroup.this.id
  database  = aws_glue_catalog_database.this.name
  query     = templatefile("${var.queries_dir}/${each.value}", { database = local.database })
}

output "athena_workgroup" {
  value = aws_athena_workgroup.this.name
}

output "athena_results_bucket_name" {
  value = aws_s3_bucket.athena_results.bucket
}

output "athena_database" {
  value = local.database
}

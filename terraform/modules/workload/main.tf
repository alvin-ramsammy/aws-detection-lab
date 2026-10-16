variable "name" {
  type = string
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# --- Network: one VPC, one public subnet, one AZ -----------------------------
# Public subnet + IGW instead of private subnet + NAT gateway: a NAT gateway is
# ~$32/month, which would dominate the lab's bill. The instance has no inbound
# rules at all, so being in a public subnet doesn't expose it.

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name}-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Strip every rule from the VPC's default security group so nothing can
# accidentally land in an allow-all group (CIS AWS 5.4).
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-default-locked" }
}

resource "aws_security_group" "workload" {
  name        = "${var.name}-workload"
  description = "No inbound. Access is via SSM Session Manager, not SSH."
  vpc_id      = aws_vpc.this.id

  egress {
    description = "Outbound for SSM agent and package updates"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Instance -----------------------------------------------------------------

resource "aws_iam_role" "workload" {
  name = "${var.name}-workload"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.workload.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "workload" {
  name = "${var.name}-workload"
  role = aws_iam_role.workload.name
}

resource "aws_instance" "workload" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.workload.id]
  iam_instance_profile   = aws_iam_instance_profile.workload.name

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  # A little steady outbound traffic so the flow logs have something to show.
  # (AL2023 ships without cron, so this uses a systemd timer.)
  user_data = <<-EOF
    #!/bin/bash
    cat > /etc/systemd/system/detlab-traffic.service <<'UNIT'
    [Service]
    Type=oneshot
    ExecStart=/usr/bin/curl -s -o /dev/null https://aws.amazon.com
    UNIT
    cat > /etc/systemd/system/detlab-traffic.timer <<'UNIT'
    [Timer]
    OnBootSec=1min
    OnUnitActiveSec=10min
    [Install]
    WantedBy=timers.target
    UNIT
    systemctl daemon-reload
    systemctl enable --now detlab-traffic.timer
  EOF

  tags = { Name = "${var.name}-workload" }

  lifecycle {
    ignore_changes = [ami]
  }
}

output "vpc_id" {
  value = aws_vpc.this.id
}

output "instance_id" {
  value = aws_instance.workload.id
}

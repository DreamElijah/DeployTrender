# ---------------------- VPC Endpoints for ECR ----------------------

# S3 Gateway Endpoint (for ECR to pull image layers from S3)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  tags = {
    Name = "s3-gateway-endpoint"
  }
}

# CloudWatch Logs endpoint (for ECS to send logs)
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnets
  security_group_ids  = [aws_security_group.crawler.id]
  private_dns_enabled = true
  tags = {
    Name = "logs-endpoint"
  }
}

# ECR API endpoint (for ECR API calls)
resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnets
  security_group_ids  = [aws_security_group.crawler.id]
  private_dns_enabled = true
  tags = {
    Name = "ecr-api-endpoint"
  }
}

# ECR DKR endpoint (for Docker image pulls)
resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnets
  security_group_ids  = [aws_security_group.crawler.id]
  private_dns_enabled = true
  tags = {
    Name = "ecr-dkr-endpoint"
  }
}
# ---------------------- VPC Endpoint for Secrets Manager ----------------------

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${var.region}.secretsmanager"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.private_subnets
  security_group_ids = [aws_security_group.crawler.id]

  private_dns_enabled = true

  tags = {
    Name = "secretsmanager-endpoint"
  }
}
resource "aws_ecs_cluster" "trend" {
  name = "trendradar"
}

resource "aws_ecr_repository" "repo" {
  name = "trendradar"
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_ecs_task_definition" "crawler" {
  family                   = "trendradar-crawler"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.exec.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "crawler"
      image     = "${aws_ecr_repository.repo.repository_url}:latest"
      essential = true
      environment = [
        { name = "REPORT_MODE", value = "incremental" }
      ]
      secrets = [
        { name = "NTFY_WEBHOOK_URL", valueFrom = aws_secretsmanager_secret.ntfy1.arn }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = "/ecs/trendradar"
          awslogs-region        = var.region
          awslogs-stream-prefix = "crawler"
        }
      }
    }
  ])
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "trendradar-crawler"
  schedule_expression = "rate(30 minutes)"
}

resource "aws_cloudwatch_event_target" "ecs_run" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "EcsCrawler"
  arn       = aws_ecs_cluster.trend.arn
  role_arn  = aws_iam_role.events.arn

  ecs_target {
    task_definition_arn = aws_ecs_task_definition.crawler.arn
    launch_type         = "FARGATE"
    network_configuration {
      subnets          = var.private_subnets
      security_groups  = [aws_security_group.crawler.id]
      assign_public_ip = false
    }
  }
}

# ---------------------- Network for Outbound Internet ----------------------

# EIP for NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"
  tags = {
    Name = "trendradar-nat-eip"
  }
}

# NAT Gateway - place in a public subnet
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = var.public_subnet_ids[0] # Uses the first public subnet

  tags = {
    Name = "trendradar-nat-gateway"
  }

  depends_on = [aws_eip.nat]
}

# Route table for private subnets to route traffic via NAT Gateway
resource "aws_route_table" "private" {
  vpc_id = var.vpc_id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "trendradar-private-rt"
  }
}

# Associate private route table with each private subnet
resource "aws_route_table_association" "private" {
  count          = length(var.private_subnets)
  subnet_id      = element(var.private_subnets, count.index)
  route_table_id = aws_route_table.private.id
}

# ---------------------- Added supporting resources ----------------------

# CloudWatch log group referenced by task definition
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/trendradar"
  retention_in_days = 14
}

# Security group for Fargate task (egress only, inbound none)
resource "aws_security_group" "crawler" {
  name        = "trendradar-crawler"
  description = "Security group for trendradar crawler Fargate task"
  vpc_id      = var.vpc_id

  # Allow HTTPS from within the VPC (for VPC endpoint communication)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.aws_vpc.selected.cidr_block)}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Data source to get the VPC CIDR block
data "aws_vpc" "selected" {
  id = var.vpc_id
}

# Secrets Manager secret for ntfy webhook / topic URL
resource "aws_secretsmanager_secret" "ntfy1" {
  name        = "trendradar/ntfy1_webhook_url"
  description = "ntfy webhook or topic URL for notifications"
}

resource "aws_secretsmanager_secret_version" "ntfy1" {
  secret_id     = aws_secretsmanager_secret.ntfy1.id
  secret_string = var.ntfy_webhook_value
}

# IAM role used by ECS tasks for execution (pull images, write logs, etc.)
resource "aws_iam_role" "exec" {
  name = "trendradar-ecs-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ecs-tasks.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "exec_ecs" {
  role       = aws_iam_role.exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Allow ECS execution role to read the ntfy1 secret
resource "aws_iam_policy" "exec_secret_read" {
  name        = "trendradar-exec-secret-read"
  description = "Allow ECS execution role to read ntfy1 secret value"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.ntfy1.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "exec_secret" {
  role       = aws_iam_role.exec.name
  policy_arn = aws_iam_policy.exec_secret_read.arn
}

# IAM role for the application task (grants read to the webhook secret only)
resource "aws_iam_role" "task" {
  name = "trendradar-ecs-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ecs-tasks.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "task_secret_read" {
  name        = "trendradar-task-secret-read"
  description = "Allow task to read ntfy webhook secret value"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.ntfy1.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "task_secret" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.task_secret_read.arn
}

# IAM role assumed by EventBridge (CloudWatch Events) to run ECS task
resource "aws_iam_role" "events" {
  name = "trendradar-events-run-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "events_run_task" {
  name        = "trendradar-events-run-task"
  description = "Allow EventBridge to run ECS Fargate task"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:RunTask", "ecs:DescribeTasks"]
        Resource = aws_ecs_task_definition.crawler.arn
        Condition = {
          ArnLike = { "ecs:cluster" = aws_ecs_cluster.trend.arn }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [aws_iam_role.exec.arn, aws_iam_role.task.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "events_attach" {
  role       = aws_iam_role.events.name
  policy_arn = aws_iam_policy.events_run_task.arn
}

# ---------------------- Variables ----------------------

variable "region" {
  type        = string
  description = "AWS region for deployment"
  default     = "ap-southeast-1"
}

variable "private_subnets" {
  type        = list(string)
  description = "Private subnet IDs for Fargate tasks"
  default     = ["subnet-0522e7d64bc53cb8c", "subnet-0b1200f8096b84e3a"]
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnet IDs for NAT Gateway"
  default     = ["subnet-00d08ce0ab941e155", "subnet-053e86c9adea89354"]
}

variable "vpc_id" {
  type        = string
  description = "VPC ID containing the private subnets"
  default     = "vpc-033310f37616fb65e"
}

variable "ntfy_webhook_value" {
  type        = string
  description = "ntfy webhook/topic URL secret string"
  sensitive   = true
}

# ---------------------- Outputs (optional) ----------------------
output "ecr_repository_url" {
  value       = aws_ecr_repository.repo.repository_url
  description = "ECR repository URL"
}

output "cluster_name" {
  value       = aws_ecs_cluster.trend.name
  description = "ECS cluster name"
}

output "task_definition_family" {
  value       = aws_ecs_task_definition.crawler.family
  description = "Task definition family"
}
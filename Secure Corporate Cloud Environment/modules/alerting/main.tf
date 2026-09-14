locals {
  log_group_name = "/aws/cloudtrail/${var.project_name}"
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = local.log_group_name
  retention_in_days = 7

  tags = merge(var.tags, {
    Name    = local.log_group_name
    Purpose = "cloudtrail-root-alerting"
  })
}

resource "aws_iam_role" "cloudtrail_logs" {
  name = "${var.project_name}-cloudtrail-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name = "${var.project_name}-cloudtrail-logs-policy"
  role = aws_iam_role.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_sns_topic" "root_activity" {
  name = "${var.project_name}-root-activity"

  tags = merge(var.tags, {
    Name    = "${var.project_name}-root-activity"
    Purpose = "root-account-alerting"
  })
}

resource "aws_sns_topic_subscription" "admin_email" {
  topic_arn = aws_sns_topic.root_activity.arn
  protocol  = "email"
  endpoint  = var.admin_email
}

resource "aws_cloudwatch_log_metric_filter" "root_activity" {
  name           = "${var.project_name}-root-account-activity"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.userIdentity.type = \"Root\") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != \"AwsServiceEvent\") }"

  metric_transformation {
    name      = "RootAccountActivity"
    namespace = "SecureCorpEnv"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_activity" {
  alarm_name          = "${var.project_name}-root-account-activity"
  alarm_description   = "Direct root-account activity was detected in CloudTrail."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.root_activity.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.root_activity.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.root_activity.arn]
}

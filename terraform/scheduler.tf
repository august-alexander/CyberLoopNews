# Ranking alert schedule — 9:00, 13:00, 17:00 America/New_York.
#
# This uses EventBridge Scheduler (aws_scheduler_schedule), NOT the
# aws_cloudwatch_event_rule pattern the fetcher/reporter use, specifically
# because Scheduler evaluates the cron in a named IANA timezone and handles
# daylight saving. A plain UTC cron would fire an hour off half the year. The
# other pipeline schedules are UTC-anchored on purpose (NVD/EDGAR windows), so
# only this user-facing alert needs the timezone-aware scheduler.
resource "aws_scheduler_schedule" "ranking" {
  name       = "${local.name_prefix}-ranking-schedule"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression          = var.ranking_schedule_expression
  schedule_expression_timezone = var.ranking_timezone

  target {
    arn      = aws_lambda_function.ranking.arn
    role_arn = aws_iam_role.scheduler.arn
  }
}

# Broadcast schedules — one per daily edition, evaluated in ranking_timezone so
# the Eastern airtimes hold across daylight saving (same reasoning as the
# ranking schedule above).
#
# Each slot gets its own schedule rather than one cron with two hours, because
# the slot name has to reach the Lambda: the morning and midday editions run on
# overlapping windows and are distinguished only by their framing. Passing it as
# target input means the show is told which edition it is instead of inferring
# it from the clock — no timezone math inside the Lambda, and a manual invoke
# can ask for either edition at any hour.
resource "aws_scheduler_schedule" "broadcast" {
  for_each = var.broadcast_slots

  name       = "${local.name_prefix}-broadcast-${each.key}-schedule"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression          = "cron(0 ${each.value} * * ? *)"
  schedule_expression_timezone = var.ranking_timezone

  target {
    arn      = aws_lambda_function.broadcast.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ slot = each.key })
  }
}

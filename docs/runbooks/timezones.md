# Timezone Convention

All CronJobs and application schedules use Hong Kong Time (HKT) explicitly.

- Set `timeZone: Asia/Hong_Kong` on every CronJob.
- Convert the intended run time to HKT instead of leaving `Etc/UTC` or a
  foreign timezone.
- Review US-market-aligned jobs when US daylight-saving time changes, because
  HKT does not observe daylight-saving time.

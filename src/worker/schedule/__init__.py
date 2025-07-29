from celery.schedules import crontab


imports = ("src.worker.jobs.test_jobs", "src.worker.tasks.bg_tasks")
task_result_expires = 30
timezone = "Africa/Lagos"

accept_content = ["json", "msgpack", "yaml"]
task_serializer = "json"
result_serializer = "json"

beat_schedule = {
    "test_cron": {
        "task": "src.worker.jobs.test_jobs.test_job",
        "schedule": crontab(minute="29", hour="11"),
    },
}

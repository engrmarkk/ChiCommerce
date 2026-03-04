from celery.schedules import crontab

imports = ("src.worker.jobs.test_jobs", "src.worker.tasks.bg_tasks")
task_result_expires = 30
timezone = "Africa/Lagos"

broker_pool_limit = None
broker_transport_options = {
    'health_check_interval': 30,  # Moves it from the URL to here
    'visibility_timeout': 3600,
    'socket_keepalive': True,
    'socket_timeout': 30,
    'retry_on_timeout': True,
}

# Important for modern Celery versions
broker_connection_retry_on_startup = True

# Ensure the worker closes connections cleanly
worker_cancel_long_running_tasks_on_connection_loss = True

accept_content = ["json", "msgpack", "yaml"]
task_serializer = "json"
result_serializer = "json"

beat_schedule = {
    "test_cron": {
        "task": "src.worker.jobs.test_jobs.test_job",
        "schedule": crontab(minute="29", hour="11"),
    },
}

from celery.schedules import crontab

imports = ("src.worker.jobs.test_jobs", "src.worker.tasks.bg_tasks")
task_result_expires = 30
timezone = "Africa/Lagos"

broker_pool_limit = None
broker_transport_options = {
    'health_check_interval': 25,      # Must be < socket_timeout
    'visibility_timeout': 3600,
    'socket_keepalive': True,
    'socket_timeout': 30,             # Lower this
    'socket_connect_timeout': 30,
    'retry_on_timeout': True,
    'max_retries': 3,
}

# Add these at the top level too
broker_connection_retry = True
broker_connection_retry_on_startup = True
broker_connection_max_retries = None   # Retry forever
result_backend_transport_options = {
    'retry_on_timeout': True,
    'socket_keepalive': True,
}

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

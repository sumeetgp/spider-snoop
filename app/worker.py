import os
from celery import Celery

# Configure Celery to use Redis as the primary broker and results backend
# Fallback to local host if not running via orchestrator
broker_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "spider_snoop_worker",
    broker=broker_url,
    backend=broker_url,
    include=["app.tasks.scan_tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Prevent a single hanging task from blocking workers permanently
    task_soft_time_limit=300,  # Raise SoftTimeLimitExceeded after 5 minutes
    task_time_limit=310        # Hard kill at 5 minutes 10 seconds
)

if __name__ == "__main__":
    celery_app.start()

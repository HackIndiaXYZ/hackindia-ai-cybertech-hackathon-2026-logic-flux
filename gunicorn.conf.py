"""Production server settings. Override via env vars."""
import multiprocessing
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = int(os.environ.get("WEB_CONCURRENCY", min(4, multiprocessing.cpu_count() * 2 + 1)))
threads = int(os.environ.get("GUNICORN_THREADS", 2))
worker_class = "gthread"
timeout = 60                 # kill hung workers
graceful_timeout = 30
keepalive = 5
max_requests = 2000          # recycle workers to contain slow leaks
max_requests_jitter = 200
accesslog = "-"
errorlog = "-"
worker_tmp_dir = "/dev/shm"  # avoids heartbeat stalls on container filesystems
preload_app = True          # create the app (DB init + seeding) once, before workers fork

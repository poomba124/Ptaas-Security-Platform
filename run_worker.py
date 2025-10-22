import eventlet
# Apply the monkey patch here, at the very beginning.
eventlet.monkey_patch()

# Now, import the celery app from your tasks file.
from tasks import celery

# This script's only job is to start the worker.
if __name__ == '__main__':
    # We build the command-line arguments that celery would normally use.
    worker_argv = [
        'worker',
        '--loglevel=info',
        '--pool=eventlet',
    ]
    # Start the worker.
    celery.worker_main(argv=worker_argv)
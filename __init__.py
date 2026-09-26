"""LLama Monitor — model-service status page.

Published standalone (this package alone) it runs in read-only mode against a
remote target host; inside the chatLlama checkout it gains passkey auth, chat
job control, provider spend cards, and model restarts. gunicorn loads
`monitor:app`, re-exported here.
"""
from .app import app  # noqa: F401

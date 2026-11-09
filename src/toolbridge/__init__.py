"""Package initialization."""
from __future__ import annotations

from pathlib import Path

try:
    from dotenv import load_dotenv

    # Auto-load .env if available, without overriding explicit environment variables
    cur = Path(__file__).resolve().parent
    for _ in range(4):
        candidate = cur / ".env"
        if candidate.is_file():
            load_dotenv(dotenv_path=candidate, override=False)
            break
    else:
        load_dotenv(override=False)
except ImportError:
    pass


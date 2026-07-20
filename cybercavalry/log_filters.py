"""Logging filters used by the split-file logging config in `settings/base.py`.

The main file (`logs/cybercavalry.log`) should carry INFO/WARNING chatter
only — everything from ERROR up already goes to `logs/error.log`, so mixing
both would duplicate every crash. `BelowErrorFilter` is attached to the
main-file handler for exactly that reason.
"""
import logging


class BelowErrorFilter(logging.Filter):
    """Allow records STRICTLY below ERROR level."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno < logging.ERROR

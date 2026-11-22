"""Scanner background tasks.

Each task (scan scheduler, feed refreshers, signature updaters, ...) is a ``Source``
the scanner runs on its own interval. Sources decide from settings whether they're
enabled, so a missing env var disables a source instead of crashing the scanner.
"""

import threading
from abc import ABC, abstractmethod

from nasscan.config import Settings


class Source(ABC):
    name: str
    interval_seconds: float

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # Set when the scanner is shutting down, for work running in threads.
        self.stopping = threading.Event()

    def enabled(self) -> bool:
        return True

    @abstractmethod
    async def run_once(self) -> None: ...

    async def close(self) -> None:  # noqa: B027 - optional hook, a no-op by default
        """Release outside resources (like an API session) when the scanner stops."""

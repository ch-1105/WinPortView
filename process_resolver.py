"""Process resolver with TTL-based cache."""

import time
import psutil


class ProcessResolver:
    """Resolves PID to process name with caching."""

    def __init__(self, cache_ttl: float = 10.0):
        self._cache: dict[int, tuple[str, float]] = {}
        self._ttl = cache_ttl

    def resolve(self, pid: int) -> str:
        """Get process name for a PID. Returns empty string on failure."""
        if pid <= 0:
            return ""

        now = time.time()
        if pid in self._cache:
            name, ts = self._cache[pid]
            if now - ts < self._ttl:
                return name

        try:
            proc = psutil.Process(pid)
            name = proc.name() or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            name = ""

        self._cache[pid] = (name, now)
        return name

    def batch_resolve(self, pids: set[int]) -> dict[int, str]:
        """Resolve a batch of PIDs at once."""
        result = {}
        for pid in pids:
            result[pid] = self.resolve(pid)
        return result

    def clear(self):
        self._cache.clear()

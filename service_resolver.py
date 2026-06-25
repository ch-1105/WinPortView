"""Service resolver using WMI batch queries."""

import threading
import time
from collections.abc import Mapping

import wmi


class ServiceResolver:
    """Maps PID → list of Windows service names using WMI batch query."""

    def __init__(self, refresh_interval: float = 30.0):
        self._cache: dict[int, list[str]] = {}
        self._lock = threading.Lock()
        self._refresh_interval = refresh_interval
        self._running = False
        self._thread: threading.Thread | None = None

    @property
    def cache(self) -> Mapping[int, list[str]]:
        """Read-only view of the current cache."""
        with self._lock:
            return dict(self._cache)

    def get(self, pid: int) -> list[str]:
        """Get service names for a given PID."""
        with self._lock:
            return self._cache.get(pid, [])

    def refresh(self) -> None:
        """Perform a single synchronous refresh of the WMI service map."""
        new_map: dict[int, list[str]] = {}
        try:
            c = wmi.WMI()
            for svc in c.Win32_Service():
                try:
                    pid = int(svc.ProcessId)
                    if pid <= 0:
                        continue
                    name = svc.Name or ""
                    if name:
                        new_map.setdefault(pid, []).append(name)
                except (ValueError, TypeError):
                    continue
        except Exception:
            # WMI failure: keep existing cache
            return

        with self._lock:
            self._cache = new_map

    def start(self) -> None:
        """Start background periodic refresh."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop background refresh."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _refresh_loop(self) -> None:
        while self._running:
            self.refresh()
            # Sleep in small chunks to respond to stop quickly
            deadline = time.time() + self._refresh_interval
            while self._running and time.time() < deadline:
                time.sleep(1)

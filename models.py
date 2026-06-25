"""Data models for the port viewer."""

from dataclasses import dataclass, field


@dataclass
class ServiceInfo:
    """Represents a Windows service."""
    name: str
    display_name: str = ""
    state: str = ""


@dataclass
class PortEntry:
    """A single port/connection row in the table."""
    protocol: str           # "TCP" or "UDP"
    local_addr: str         # "127.0.0.1"
    local_port: int         # 8080
    remote_addr: str        # "0.0.0.0" or peer address
    remote_port: int        # 0 or peer port
    state: str              # "LISTEN", "ESTABLISHED", etc.
    pid: int                # owning process ID
    process_name: str = ""  # resolved by ProcessResolver
    services: list[str] = field(default_factory=list)  # resolved service names

    # Display helpers
    @property
    def local(self) -> str:
        return f"{self.local_addr}:{self.local_port}"

    @property
    def remote(self) -> str:
        if not self.remote_addr or self.remote_addr == "0.0.0.0":
            return "*:*"
        return f"{self.remote_addr}:{self.remote_port}"

    @property
    def service_display(self) -> str:
        return ", ".join(self.services) if self.services else ""

"""Port scanner using psutil."""

import socket

import psutil

from models import PortEntry


def scan_ports() -> list[PortEntry]:
    """Scan all active TCP/UDP ports and return PortEntry list."""
    results = []
    for conn in psutil.net_connections(kind='all'):
        try:
            proto = _proto_name(conn.type)
            state = conn.status or "UNKNOWN"

            laddr = conn.laddr.ip if conn.laddr else "0.0.0.0"
            lport = conn.laddr.port if conn.laddr else 0
            raddr = conn.raddr.ip if conn.raddr else ""
            rport = conn.raddr.port if conn.raddr else 0

            # UDP has no connection state; show as "ACTIVE" if bound
            if proto == "UDP" and state == "NONE":
                state = "ACTIVE"

            results.append(PortEntry(
                protocol=proto,
                local_addr=laddr,
                local_port=lport,
                remote_addr=raddr,
                remote_port=rport,
                state=state,
                pid=conn.pid or 0,
            ))
        except Exception:
            continue  # Skip entries that fail (e.g. PID already gone)

    # Sort: LISTEN first, then by local port
    results.sort(key=lambda e: (e.state != "LISTEN", e.local_port))
    return results


def _proto_name(conn_type: int) -> str:
    """Map socket.SOCK_STREAM / SOCK_DGRAM to string."""
    if conn_type == socket.SOCK_STREAM:
        return "TCP"
    if conn_type == socket.SOCK_DGRAM:
        return "UDP"
    return f"UNKNOWN({conn_type})"

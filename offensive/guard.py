"""Lab-target safety guard for the offensive demo scripts.

Kept as a self-contained copy (not a cross-project import) so this project
remains an independent deploy unit, matching the pattern used by every
sibling project's ``offensive/guard.py``.
"""

from __future__ import annotations

import ipaddress
import socket


class LabGuardError(Exception):
    pass


def is_lab_target(host: str) -> bool:
    """True if ``host`` (IP or hostname) resolves to loopback/private/link-local."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def require_lab_target(host: str, override: bool = False) -> None:
    """Raise :class:`LabGuardError` unless ``host`` is a lab target or ``override`` is set."""
    if override:
        return
    if not is_lab_target(host):
        raise LabGuardError(
            f"{host!r} is not a loopback/private/link-local lab target. "
            "Pass override=True / --i-understand-lab if you are explicitly authorized to test it."
        )

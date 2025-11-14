"""LDAP Data Logger.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Protocol

from ldap_protocol import LDAPRequestMessage
from ldap_protocol.messages import LDAPMessage, LDAPResponseMessage


class _LoggingProtocol(Protocol):
    """Logging protocol interface."""

    def debug(self, msg: str) -> None:
        """Log debug message."""
        ...

    def info(self, msg: str) -> None:
        """Log info message."""
        ...


class DataLogger:
    """LDAP Data Logger."""

    def __init__(
        self,
        logger: _LoggingProtocol,
        is_full: bool = False,
        prefix: str = "",
    ) -> None:
        """Set logging mode."""
        self.l = logger
        self.prefix = prefix
        if is_full:
            self.req_log = self._req_log_full
            self.rsp_log = self._resp_log_full
        else:
            self.req_log = self.rsp_log = self._log_short

    def _req_log_full(self, addr: str, msg: LDAPRequestMessage) -> None:
        self.l.debug(
            f"\n{self.prefix}From: {addr!r}\n{msg.name}[{msg.message_id}]: "
            f"{msg.model_dump_json()}\n",
        )

    def _resp_log_full(self, addr: str, msg: LDAPResponseMessage) -> None:
        self.l.debug(
            f"\n{self.prefix}To: {addr!r}\n{msg.name}[{msg.message_id}]: "
            f"{msg.model_dump_json()}"[:3000],
        )

    def _log_short(self, addr: str, msg: LDAPMessage) -> None:
        self.l.info(f"\n{self.prefix}{addr!r}: {msg.name}[{msg.message_id}]\n")

"""LDAP tcp server.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from loguru import Logger

from ldap_protocol import LDAPRequestMessage
from ldap_protocol.messages import LDAPMessage, LDAPResponseMessage


class DataLogger:
    """LDAP Data Logger."""

    def __init__(self, logger: Logger, full: bool = False) -> None:
        """Set logging mode."""
        self.l = logger
        if full:
            self.req_log = self._req_log_full
            self.rsp_log = self._resp_log_full
        else:
            self.req_log = self.rsp_log = self._log_short

    def _req_log_full(self, addr: str, msg: LDAPRequestMessage) -> None:
        self.l.debug(
            f"\nFrom: {addr!r}\n{msg.name}[{msg.message_id}]: "
            f"{msg.model_dump_json()}\n",
        )

    def _resp_log_full(self, addr: str, msg: LDAPResponseMessage) -> None:
        self.l.debug(
            f"\nTo: {addr!r}\n{msg.name}[{msg.message_id}]: "
            f"{msg.model_dump_json()}"[:3000],
        )

    def _log_short(self, addr: str, msg: LDAPMessage) -> None:
        self.l.info(f"\n{addr!r}: {msg.name}[{msg.message_id}]\n")

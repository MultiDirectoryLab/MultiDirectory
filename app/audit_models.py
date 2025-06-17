"""MultiDirectory LDAP models for audit.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase, AsyncAttrs):
    """Declarative base model."""


class AuditLog(Base):
    """Audit log model."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    content: Mapped[dict] = mapped_column(postgresql.JSON, nullable=False)
    server_delivery_status: Mapped[dict] = mapped_column(
        postgresql.JSON, nullable=False
    )
    first_failed_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    retry_count: Mapped[int] = mapped_column(nullable=False, default=0)

    @property
    def syslog_message(self) -> str:
        """Get syslog message."""
        return f"User {self.content['username']} {self.content['event_type']}"

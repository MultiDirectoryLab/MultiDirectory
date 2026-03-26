"""LDF version DTOs."""

from dataclasses import dataclass
from datetime import datetime

from enums import LdfVersionStatus


@dataclass
class LdfVersionDTO:
    """LDF version processing DTO."""

    version: str
    d_create: datetime | None = None
    status: LdfVersionStatus | None = None

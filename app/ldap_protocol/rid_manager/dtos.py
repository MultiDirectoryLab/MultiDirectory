"""RID Manager DTOs.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass


@dataclass
class RIDSetAllocationParamsDTO:
    """RID Set DTO."""

    next_rid: int
    previous_allocation_pool: int
    allocation_pool: int

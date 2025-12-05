"""Domain controller info Dataclasses.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class DomainControllerInfo:
    """DC info dataclass."""

    net_bios_domain: str
    net_bios_hostname: str
    unc: str
    dns: str
    dns_forest: str
    object_sid: str
    object_guid: str

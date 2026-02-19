"""SystemFlags helpers for LDAP schema objects.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from __future__ import annotations

from enum import IntFlag

from ldap_protocol.ldap_schema.dto import AttributeTypeDTO


class AttributeTypeSystemFlags(IntFlag):
    """SystemFlags for attributeSchema objects in AD.

    Bits from 7 to 25 unused. Must be zero and ignored.
    ms-adts/1e38247d-8234-4273-9de3-bbf313548631
    """

    ATTR_NOT_REPLICATED = 0x00000001  # 31
    ATTR_REQ_PARTIAL_SET_MEMBER = 0x00000002  # 30
    ATTR_IS_CONSTRUCTED = 0x00000004  # 29
    ATTR_IS_OPERATIONAL = 0x00000008  # 28
    SCHEMA_BASE_OBJECT = 0x00000010  # 27
    ATTR_IS_RDN = 0x00000020  # 26
    DISALLOW_MOVE_ON_DELETE = 0x02000000  # 6
    DOMAIN_DISALLOW_MOVE = 0x04000000  # 5
    DOMAIN_DISALLOW_RENAME = 0x08000000  # 4
    CONFIG_ALLOW_LIMITED_MOVE = 0x10000000  # 3
    CONFIG_ALLOW_MOVE = 0x20000000  # 2
    CONFIG_ALLOW_RENAME = 0x40000000  # 1
    DISALLOW_DELETE = 0x80000000  # 0


class AttributeTypeSystemFlagsUseCase:
    def is_attr_replicated(
        self,
        attribute_type_dto: AttributeTypeDTO,
    ) -> bool:
        """Check if attribute is replicated based on system_flags."""
        print(
            bool(
                attribute_type_dto.system_flags
                & AttributeTypeSystemFlags.ATTR_NOT_REPLICATED,
            ),
        )
        print(
            not bool(
                attribute_type_dto.system_flags
                & AttributeTypeSystemFlags.ATTR_NOT_REPLICATED,
            ),
        )
        return not bool(
            attribute_type_dto.system_flags
            & AttributeTypeSystemFlags.ATTR_NOT_REPLICATED,
        )

    def set_attr_replication_flag(
        self,
        attribute_type_dto: AttributeTypeDTO,
        need_to_replicate: bool,
    ) -> AttributeTypeDTO:
        """Set/clear replication flag in systemFlags."""
        if not need_to_replicate:
            attribute_type_dto.system_flags = int(
                attribute_type_dto.system_flags
                | AttributeTypeSystemFlags.ATTR_NOT_REPLICATED,
            )
        else:
            attribute_type_dto.system_flags = int(
                attribute_type_dto.system_flags
                & ~AttributeTypeSystemFlags.ATTR_NOT_REPLICATED,
            )

        return attribute_type_dto

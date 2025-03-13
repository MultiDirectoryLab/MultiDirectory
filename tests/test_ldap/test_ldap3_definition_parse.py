"""Test parse ldap3 definition.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.utils.ldap3_parser import Ldap3Parser
from models import AttributeType, ObjectClass

test_ldap3_parse_attribute_types_dataset = [
    [
        "( 1.2.840.113556.1.4.149 NAME 'attributeSecurityGUID' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' SINGLE-VALUE )",  # noqa: E501
        "( 1.2.840.113556.1.4.1703 NAME 'msDS-FilterContainers' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )",  # noqa: E501
        "( 1.2.840.113556.1.4.655 NAME 'legacyExchangeDN' SYNTAX '1.2.840.113556.1.4.905' SINGLE-VALUE )",  # noqa: E501
        "( 1.2.840.113556.1.4.21 NAME 'cOMProgID' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )",  # noqa: E501
        "( 1.2.840.113556.1.4.2147 NAME 'msDNS-PropagationTime' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )",  # noqa: E501
        "( 1.2.840.113556.1.6.18.1.301 NAME 'msSFU30KeyAttributes' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )",  # noqa: E501
        "( 1.2.840.113556.1.4.686 NAME 'domainID' SYNTAX '1.3.6.1.4.1.1466.115.121.1.12' SINGLE-VALUE )",  # noqa: E501
        "( 1.2.840.113556.1.6.13.3.23 NAME 'msDFSR-ReplicationGroupGuid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' SINGLE-VALUE )",  # noqa: E501
        "( 1.2.840.113556.1.4.818 NAME 'productCode' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' SINGLE-VALUE )",  # noqa: E501
        "( 1.3.6.1.1.1.1.18 NAME 'oncRpcNumber' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )",  # noqa: E501
        "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )",  # noqa: E501
        "( 1.2.840.113556.1.4.375 NAME 'systemFlags' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE NO-USER-MODIFICATION )",  # noqa: E501
    ],
]


@pytest.mark.parametrize(
    "test_dataset",
    test_ldap3_parse_attribute_types_dataset,
)
@pytest.mark.asyncio
async def test_ldap3_parse_attribute_types(test_dataset: list[str]) -> None:
    """Test parse ldap3 attribute types."""
    for raw_definition in test_dataset:
        attribute_type: AttributeType = (
            Ldap3Parser.create_attribute_type_by_raw(raw_definition)
        )

        assert raw_definition == attribute_type.get_raw_definition()


test_ldap3_parse_object_classes_dataset = [
    [
        "( 1.2.840.113556.1.5.152 NAME 'intellimirrorGroup' SUP top STRUCTURAL )",  # noqa: E501
        "( 1.2.840.113556.1.5.262 NAME 'msImaging-PSPs' SUP container STRUCTURAL )",  # noqa: E501
        "( 1.2.840.113556.1.5.27 NAME 'rpcEntry' SUP connectionPoint ABSTRACT )",  # noqa: E501
    ],
]


@pytest.mark.parametrize(
    "test_dataset",
    test_ldap3_parse_object_classes_dataset,
)
@pytest.mark.asyncio
async def test_ldap3_parse_object_classes(
    session: AsyncSession,
    test_dataset: list[str],
) -> None:
    """Test parse ldap3 object classes."""
    for raw_definition in test_dataset:
        object_class: ObjectClass = (
            await Ldap3Parser.create_object_class_by_raw(
                session=session,
                raw_definition=raw_definition,
            )
        )

        assert raw_definition == object_class.get_raw_definition()

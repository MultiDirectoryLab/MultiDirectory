"""LDAP schema parsing functions."""

from ldap3.protocol.rfc4512 import AttributeTypeInfo, ObjectClassInfo

ATTRIBUTE_TYPES_FILE_PATH: str = "extra/adTypes.txt"
OBJECT_CLASSES_FILE_PATH: str = "extra/adClasses.txt"


def get_object_class_infos_from_txt_definition() -> dict[str, ObjectClassInfo]:
    """Parse AD class definition from txt.

    Example:
    ( 1.2.840.113556.1.5.36 NAME 'volume' SUP connectionPoint STRUCTURAL MUST (uNCName ) MAY (contentIndexingAllowed $ lastContentIndexed ) )
    ( 1.2.840.113556.1.5.82 NAME 'rpcProfile' SUP rpcEntry STRUCTURAL )
    ( 1.2.840.113556.1.5.80 NAME 'rpcGroup' SUP rpcEntry STRUCTURAL MAY (rpcNsGroup $ rpcNsObjectID ) )

    References:
    RFC 4512 - LDAP: Directory Information Models
    RFC 4517 - LDAP: Syntaxes and Matching Rules
    RFC 4519 - LDAP: Schema for User Applications.

    """  # noqa: E501
    with open(OBJECT_CLASSES_FILE_PATH) as file:
        return ObjectClassInfo.from_definition(definitions=list(file))


def get_attribute_type_infos_from_txt_definition() -> dict[
    str, AttributeTypeInfo
]:
    """Parse AD types definition from txt.

    Example:
    ( 1.2.840.113556.1.4.609 NAME 'sIDHistory' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' )
    ( 1.2.840.113556.1.4.145 NAME 'revision' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )

    References:
    RFC 4512 - LDAP: Directory Information Models
    RFC 4517 - LDAP: Syntaxes and Matching Rules
    RFC 4519 - LDAP: Schema for User Applications.

    """  # noqa: E501
    with open(ATTRIBUTE_TYPES_FILE_PATH) as file:
        return AttributeTypeInfo.from_definition(definitions=list(file))

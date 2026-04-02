"""Constants for attribute type property names."""

from enum import StrEnum


class AttributeTypeAttributeNames(StrEnum):
    """Attribute Type attribute names."""

    OID = "attributeID"
    NAME = "name"
    OBJECT_CLASS = "objectClass"
    LDAP_DISPLAY_NAME = "lDAPDisplayName"
    SYNTAX = "attributeSyntax"
    SINGLE_VALUE = "isSingleValued"
    NO_USER_MODIFICATION = "systemOnly"
    SYSTEM_FLAGS = "systemFlags"
    IS_INCLUDED_ANR = "aNR"

"""Subcontainers for requests/responses.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, StrEnum


class Scope(IntEnum):
    """Enum for search request.

    ```
    BASE_OBJECT = 0
    SINGLE_LEVEL = 1
    WHOLE_SUBTREE = 2
    SUBORDINATE_SUBTREE = 3
    ```
    """

    BASE_OBJECT = 0
    SINGLE_LEVEL = 1
    WHOLE_SUBTREE = 2
    SUBORDINATE_SUBTREE = 3


class DerefAliases(IntEnum):
    """Enum for search request.

    ```
    NEVER_DEREF_ALIASES = 0
    DEREF_IN_SEARCHING = 1
    DEREF_FINDING_BASE_OBJ = 2
    DEREF_ALWAYS = 3
    ```
    """

    NEVER_DEREF_ALIASES = 0
    DEREF_IN_SEARCHING = 1
    DEREF_FINDING_BASE_OBJ = 2
    DEREF_ALWAYS = 3


class LDAPMatchingRule(StrEnum):
    """Enum for LDAP Matching Rules (extensibleMatch).

    ```
    LDAP_MATCHING_RULE_BIT_AND = "1.2.840.113556.1.4.803"
    LDAP_MATCHING_RULE_BIT_OR = "1.2.840.113556.1.4.804"
    LDAP_MATCHING_RULE_TRANSITIVE_EVAL = "1.2.840.113556.1.4.1941"
    LDAP_MATCHING_RULE_DN_WITH_DATA = "1.2.840.113556.1.4.2253"
    ```
    """

    LDAP_MATCHING_RULE_BIT_AND = "1.2.840.113556.1.4.803"
    LDAP_MATCHING_RULE_BIT_OR = "1.2.840.113556.1.4.804"
    LDAP_MATCHING_RULE_TRANSITIVE_EVAL = "1.2.840.113556.1.4.1941"
    LDAP_MATCHING_RULE_DN_WITH_DATA = "1.2.840.113556.1.4.2253"


class AuditEventType(StrEnum):
    """Enum for audit event type.

    ```
    LDAP_ADD = "ldap_add"
    LDAP_AUTH = "ldap_auth"
    LDAP_DELETE = "ldap_delete"
    LDAP_MODIFY = "ldap_modify"
    LDAP_MODIFY_DN = "ldap_modify_dn"
    LDAP_EXTEND = "ldap_extend"

    API_AUTH = "api_auth"
    API_ADD = "api_add"
    API_DELETE = "api_delete"
    API_MODIFY = "api_modify"
    API_MODIFY_DN = "api_modify_dn"
    API_EXTEND = "api_extend"
    ```
    """

    LDAP_ADD = "ldap_add"
    LDAP_AUTH = "ldap_auth"
    LDAP_DELETE = "ldap_delete"
    LDAP_MODIFY = "ldap_modify"
    LDAP_MODIFY_DN = "ldap_modify_dn"
    LDAP_EXTEND = "ldap_extend"

    API_AUTH = "api_auth"
    API_ADD = "api_add"
    API_DELETE = "api_delete"
    API_MODIFY = "api_modify"
    API_MODIFY_DN = "api_modify_dn"
    API_EXTEND = "api_extend"


class AuditOperation(StrEnum):
    """
    Enum for representing common operations.

    Attributes:
        GREATER_THAN: Represents the 'greater than' operation ('>')
        LESS_THAN: Represents the 'less than' operation ('<')
        NOT: Represents the 'not' operation ('!')
        BITWISE_AND: Represents the 'bitwise and' operation ('&')
    """

    GREATER_THAN = ">"
    LESS_THAN = "<"
    NOT = "!"
    BITWISE_AND = "&"


class ProtocolOp(IntEnum):
    """
    Enum for LDAP protocol operations.

    Attributes:
        BIND_REQUEST: Represents the BindRequest operation (0)
        UNBIND_REQUEST: Represents the UnbindRequest operation (1)
        SEARCH_REQUEST: Represents the SearchRequest operation (3)
        MODIFY_REQUEST: Represents the ModifyRequest operation (6)
        ADD_REQUEST: Represents the AddRequest operation (8)
        DELETE_REQUEST: Represents the DelRequest operation (10)
        MODIFY_DN_REQUEST: Represents the ModifyDNRequest operation (12)
        COMPARE_REQUEST: Represents the CompareRequest operation (14)
        ABANDON_REQUEST: Represents the AbandonRequest operation (16)
        EXTENDED_REQUEST: Represents the ExtendedRequest operation (23)
    """

    BIND_REQUEST = 0
    UNBIND_REQUEST = 1
    SEARCH_REQUEST = 3
    MODIFY_REQUEST = 6
    ADD_REQUEST = 8
    DELETE_REQUEST = 10
    MODIFY_DN_REQUEST = 12
    COMPARE_REQUEST = 14
    ABANDON_REQUEST = 16
    EXTENDED_REQUEST = 23

"""Subcontainers for requests/responses.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, StrEnum, unique


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


class ProtocolRequests(IntEnum):
    """Enum for LDAP requests.

    Attributes:
        BIND: Represents the BindRequest operation (0)
        UNBIND: Represents the UnbindRequest operation (2)
        SEARCH: Represents the SearchRequest operation (3)
        MODIFY: Represents the ModifyRequest operation (6)
        ADD: Represents the AddRequest operation (8)
        DELETE: Represents the DelRequest operation (10)
        COMPARE: Represents the CompareRequest operation (14)
        ABANDON: Represents the AbandonRequest operation (16)
        EXTENDED: Represents the ExtendedRequest operation (23)
        MODIFY_DN: Represents the ModifyDNRequest operation (12)

    """

    BIND = 0
    UNBIND = 2
    SEARCH = 3
    MODIFY = 6
    ADD = 8
    DELETE = 10
    MODIFY_DN = 12
    COMPARE = 14
    ABANDON = 16
    EXTENDED = 23


@unique
class ProtocolResponse(IntEnum):
    """Enum for LDAP resposnes.

    Attributes:
        BIND: Represents the BindResponse operation (1)
        SEARCH_RES: Represents the SearchResultEntry operation (4)
        SEARCH_RE: Represents the SearchResultDone operation (5)
        MODIFY: Represents the ModifyResponse operation (7)
        ADD: Represents the AddResponse operation (9)
        DELETE: Represents the DelResponse operation (11)
        MODIFY_DN: Represents the ModifyDNResponse operation (13)
        COMPARE: Represents the CompareResponse operation (15)
        SEARCH_RESULT_: Represents the SearchResultReference operation (19)
        EXTENDED: Represents the ExtendedResponse operation (24)
        INTERMEDIATE: Represents the IntermediateResponse operation (25)

    """

    BIND = 1
    SEARCH_RESULT_ENTRY = 4
    SEARCH_RESULT_DONE = 5
    MODIFY = 7
    ADD = 9
    DELETE = 11
    MODIFY_DN = 13
    COMPARE = 15
    EXTENDED = 24
    INTERMEDIATE = 25
    SEARCH_RESULT_REFERENCE = 19


@unique
class OperationEvent(IntEnum):
    """Enum for operation events. Includes all LDAP requests."""

    BIND = ProtocolRequests.BIND.value
    UNBIND = ProtocolRequests.UNBIND.value
    SEARCH = ProtocolRequests.SEARCH.value
    MODIFY = ProtocolRequests.MODIFY.value
    ADD = ProtocolRequests.ADD.value
    DELETE = ProtocolRequests.DELETE.value
    MODIFY_DN = ProtocolRequests.MODIFY_DN.value
    COMPARE = ProtocolRequests.COMPARE.value
    ABANDON = ProtocolRequests.ABANDON.value
    EXTENDED = ProtocolRequests.EXTENDED.value
    CHANGE_PASSWORD = 40
    AFTER_2FA = 41

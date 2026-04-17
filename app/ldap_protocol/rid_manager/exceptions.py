"""RID Manager exceptions."""

from enum import IntEnum

from errors import BaseDomainException


class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    RID_MANAGER_NOT_FOUND_ERROR = 1
    RID_AVAILABLE_POOL_NOT_FOUND_ERROR = 2
    RID_NEXT_RID_NOT_FOUND_ERROR = 3
    RID_SET_NOT_FOUND_ERROR = 4
    RID_DOMAIN_IDENTIFIER_NOT_FOUND_ERROR = 5
    RID_DOMAIN_CONTROLLER_NOT_FOUND_ERROR = 6
    RID_BASE_DOMAIN_NOT_FOUND_ERROR = 7
    RID_SYSTEM_CONTAINER_NOT_FOUND_ERROR = 8
    RID_ALLOCATION_POOL_NOT_FOUND_ERROR = 9
    RID_PREVIOUS_ALLOCATION_POOL_NOT_FOUND_ERROR = 10
    RID_POOL_EXCEEDED_ERROR = 11
    RID_OBJECT_SID_NOT_FOUND_ERROR = 12


class RIDManagerError(BaseDomainException):
    """RID Manager error."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR


class RIDManagerNotFoundError(RIDManagerError):
    """RID Manager not found error."""

    code = ErrorCodes.RID_MANAGER_NOT_FOUND_ERROR


class RIDManagerAvailablePoolNotFoundError(RIDManagerError):
    """RID Manager available pool not found error."""

    code = ErrorCodes.RID_AVAILABLE_POOL_NOT_FOUND_ERROR


class RIDManagerRidNextRIDNotFoundError(RIDManagerError):
    """RID Manager next RID not found error."""

    code = ErrorCodes.RID_NEXT_RID_NOT_FOUND_ERROR


class RIDManagerRidSetNotFoundError(RIDManagerError):
    """RID Manager RID Set not found error."""

    code = ErrorCodes.RID_SET_NOT_FOUND_ERROR


class RIDManagerDomainIdentifierNotFoundError(RIDManagerError):
    """RID Manager domain identifier not found error."""

    code = ErrorCodes.RID_DOMAIN_IDENTIFIER_NOT_FOUND_ERROR


class RIDManagerDomainControllerNotFoundError(RIDManagerError):
    """RID Manager domain controller not found error."""

    code = ErrorCodes.RID_DOMAIN_CONTROLLER_NOT_FOUND_ERROR


class RIDManagerSystemContainerNotFoundError(RIDManagerError):
    """RID Manager system container not found error."""

    code = ErrorCodes.RID_SYSTEM_CONTAINER_NOT_FOUND_ERROR


class RIDManagerRidAllocationPoolNotFoundError(RIDManagerError):
    """RID Manager RID allocation pool not found error."""

    code = ErrorCodes.RID_ALLOCATION_POOL_NOT_FOUND_ERROR


class RIDManagerRidPreviousAllocationPoolNotFoundError(RIDManagerError):
    """RID Manager RID previous allocation pool not found error."""

    code = ErrorCodes.RID_PREVIOUS_ALLOCATION_POOL_NOT_FOUND_ERROR


class RIDManagerPoolExceededError(RIDManagerError):
    """RID Manager pool exceeded error."""

    code = ErrorCodes.RID_POOL_EXCEEDED_ERROR


class RIDManagerBaseDomainNotFoundError(RIDManagerError):
    """RID Manager base domain not found error."""

    code = ErrorCodes.RID_BASE_DOMAIN_NOT_FOUND_ERROR


class RIDManagerObjectSIDNotFoundError(RIDManagerError):
    """RID Manager object SID not found error."""

    code = ErrorCodes.RID_OBJECT_SID_NOT_FOUND_ERROR

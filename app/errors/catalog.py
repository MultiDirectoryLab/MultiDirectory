"""Exception → ErrorCode catalog.

Centralized mapping from exception classes to internal ErrorCode values.
"""

from enums import ErrorCode

_NAME_TO_CODE: dict[str, ErrorCode] = {
    "AuditAlreadyExistsError": ErrorCode.ENTITY_ALREADY_EXISTS,
    "AuditNotFoundError": ErrorCode.ENTITY_NOT_FOUND,
    "AuthenticationError": ErrorCode.UNAUTHORIZED,
    "ForbiddenError": ErrorCode.UNAUTHORIZED,
    "IdentityError": ErrorCode.UNAUTHORIZED,
    "LoginFailedError": ErrorCode.INVALID_CREDENTIALS,
    "ModifyForbiddenError": ErrorCode.PERMISSION_DENIED,
    "UnauthorizedError": ErrorCode.UNAUTHORIZED,
    "IntegrityError": ErrorCode.DATABASE_ERROR,
    "DNSConnectionError": ErrorCode.UNHANDLED_ERROR,
    "DNSError": ErrorCode.UNHANDLED_ERROR,
    "DNSNotImplementedError": ErrorCode.UNHANDLED_ERROR,
    "AlreadyConfiguredError": ErrorCode.INVALID_OPERATION,
    "AttributeError": ErrorCode.BAD_REQUEST,
    "ConnectionAbortedError": ErrorCode.UNHANDLED_ERROR,
    "Exception": ErrorCode.UNHANDLED_ERROR,
    "InvalidCredentialsError": ErrorCode.INVALID_CREDENTIALS,
    "KRBAPIError": ErrorCode.UNHANDLED_ERROR,
    "KeyError": ErrorCode.BAD_REQUEST,
    "LookupError": ErrorCode.ENTITY_NOT_FOUND,
    "NoValidDistinguishedNameError": ErrorCode.INVALID_INPUT,
    "NoValidGroupsError": ErrorCode.INVALID_INPUT,
    "NotImplementedError": ErrorCode.UNHANDLED_ERROR,
    "PermissionError": ErrorCode.PERMISSION_DENIED,
    "RecursionError": ErrorCode.UNHANDLED_ERROR,
    "RuntimeError": ErrorCode.UNHANDLED_ERROR,
    "SystemError": ErrorCode.UNHANDLED_ERROR,
    "TypeError": ErrorCode.BAD_REQUEST,
    "UserNotFoundError": ErrorCode.ENTITY_NOT_FOUND,
    "ValidationError": ErrorCode.VALIDATION_ERROR,
    "ValueError": ErrorCode.VALIDATION_ERROR,
    "KRBAPIPrincipalNotFoundError": ErrorCode.ENTITY_NOT_FOUND,
    "KerberosBaseDnNotFoundError": ErrorCode.UNHANDLED_ERROR,
    "KerberosConflictError": ErrorCode.INVALID_OPERATION,
    "KerberosDependencyError": ErrorCode.UNHANDLED_ERROR,
    "KerberosError": ErrorCode.UNHANDLED_ERROR,
    "KerberosNotFoundError": ErrorCode.ENTITY_NOT_FOUND,
    "KerberosUnavailableError": ErrorCode.UNHANDLED_ERROR,
    "AttributeTypeAlreadyExistsError": ErrorCode.ENTITY_ALREADY_EXISTS,
    "AttributeTypeCantModifyError": ErrorCode.PERMISSION_DENIED,
    "AttributeTypeError": ErrorCode.BAD_REQUEST,
    "AttributeTypeNotFoundError": ErrorCode.ENTITY_NOT_FOUND,
    "EntityTypeAlreadyExistsError": ErrorCode.ENTITY_ALREADY_EXISTS,
    "EntityTypeCantModifyError": ErrorCode.PERMISSION_DENIED,
    "EntityTypeNotFoundError": ErrorCode.ENTITY_NOT_FOUND,
    "EntityTypeTypeError": ErrorCode.BAD_REQUEST,
    "ObjectClassAlreadyExistsError": ErrorCode.ENTITY_ALREADY_EXISTS,
    "ObjectClassCantModifyError": ErrorCode.PERMISSION_DENIED,
    "ObjectClassNotFoundError": ErrorCode.ENTITY_NOT_FOUND,
    "ObjectClassTypeError": ErrorCode.BAD_REQUEST,
    "MFAError": ErrorCode.UNAUTHORIZED,
    "MFAIdentityError": ErrorCode.UNAUTHORIZED,
    "MFATokenError": ErrorCode.INVALID_CREDENTIALS,
    "MissingMFACredentialsError": ErrorCode.UNAUTHORIZED,
    "_MFAConnectError": ErrorCode.UNHANDLED_ERROR,
    "_MFAMissconfiguredError": ErrorCode.INVALID_OPERATION,
    "_MultifactorError": ErrorCode.UNAUTHORIZED,
    "NetworkPolicyError": ErrorCode.UNAUTHORIZED,
    "PasswordPolicyAlreadyExistsError": ErrorCode.ENTITY_ALREADY_EXISTS,
    "PasswordPolicyBaseError": ErrorCode.VALIDATION_ERROR,
    "PasswordPolicyError": ErrorCode.PASSWORD_POLICY_VIOLATION,
    "PasswordPolicyNotFoundError": ErrorCode.ENTITY_NOT_FOUND,
    "AccessControlEntryAddError": ErrorCode.INVALID_OPERATION,
    "AccessControlEntryNotFoundError": ErrorCode.ENTITY_NOT_FOUND,
    "AccessControlEntryUpdateError": ErrorCode.INVALID_OPERATION,
    "RoleError": ErrorCode.BAD_REQUEST,
    "RoleNotFoundError": ErrorCode.ENTITY_NOT_FOUND,
}


class ErrorCatalog:
    """Resolve ErrorCode by exception class name."""

    def resolve(
        self,
        exc: BaseException | type[BaseException],
    ) -> ErrorCode | None:
        """Resolve ErrorCode by exception class name."""
        if isinstance(exc, type):
            name = exc.__name__
        else:
            name = exc.__class__.__name__
        return _NAME_TO_CODE.get(name)

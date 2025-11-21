"""Exception → ErrorCode catalog.

Centralized mapping from exception classes to internal ErrorCode values.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enums import ErrorCode

_NAME_TO_CODE: dict[str, ErrorCode] = {
    "AuditAlreadyExistsError": ErrorCode.AUDIT_ALREADY_EXISTS,
    "AuditNotFoundError": ErrorCode.AUDIT_NOT_FOUND,
    "AuthenticationError": ErrorCode.AUTHENTICATION_ERROR,
    "ForbiddenError": ErrorCode.FORBIDDEN_ERROR,
    "IdentityError": ErrorCode.IDENTITY_ERROR,
    "LoginFailedError": ErrorCode.LOGIN_FAILED,
    "ModifyForbiddenError": ErrorCode.MODIFY_FORBIDDEN,
    "UnauthorizedError": ErrorCode.UNAUTHORIZED,
    "IntegrityError": ErrorCode.INTEGRITY_ERROR,
    "DNSConnectionError": ErrorCode.DNS_CONNECTION_ERROR,
    "DNSError": ErrorCode.DNS_ERROR,
    "DNSNotImplementedError": ErrorCode.DNS_NOT_IMPLEMENTED,
    "AlreadyConfiguredError": ErrorCode.ALREADY_CONFIGURED,
    "AttributeError": ErrorCode.ATTRIBUTE_ERROR,
    "ConnectionAbortedError": ErrorCode.CONNECTION_ABORTED,
    "Exception": ErrorCode.EXCEPTION,
    "InvalidCredentialsError": ErrorCode.INVALID_CREDENTIALS,
    "KRBAPIError": ErrorCode.KRB_API_ERROR,
    "KRBAPIChangePasswordError": ErrorCode.KERBEROS_CHANGE_PASSWORD_ERROR,
    "KeyError": ErrorCode.KEY_ERROR,
    "LookupError": ErrorCode.LOOKUP_ERROR,
    "NoValidDistinguishedNameError": ErrorCode.NO_VALID_DISTINGUISHED_NAME,
    "NoValidGroupsError": ErrorCode.NO_VALID_GROUPS,
    "NotImplementedError": ErrorCode.NOT_IMPLEMENTED,
    "PermissionError": ErrorCode.PERMISSION_ERROR,
    "RecursionError": ErrorCode.RECURSION_ERROR,
    "RuntimeError": ErrorCode.RUNTIME_ERROR,
    "SystemError": ErrorCode.SYSTEM_ERROR,
    "TypeError": ErrorCode.TYPE_ERROR,
    "UserNotFoundError": ErrorCode.USER_NOT_FOUND,
    "ValidationError": ErrorCode.VALIDATION_ERROR,
    "ValueError": ErrorCode.VALUE_ERROR,
    "KRBAPIPrincipalNotFoundError": ErrorCode.KRB_API_PRINCIPAL_NOT_FOUND,
    "KerberosBaseDnNotFoundError": ErrorCode.KERBEROS_BASE_DN_NOT_FOUND,
    "KerberosConflictError": ErrorCode.KERBEROS_CONFLICT,
    "KerberosDependencyError": ErrorCode.KERBEROS_DEPENDENCY,
    "KerberosError": ErrorCode.KERBEROS_ERROR,
    "KerberosNotFoundError": ErrorCode.KERBEROS_NOT_FOUND,
    "KerberosUnavailableError": ErrorCode.KERBEROS_UNAVAILABLE,
    "AttributeTypeAlreadyExistsError": ErrorCode.ATTRIBUTE_TYPE_ALREADY_EXISTS,
    "AttributeTypeCantModifyError": ErrorCode.ATTRIBUTE_TYPE_CANT_MODIFY,
    "AttributeTypeError": ErrorCode.ATTRIBUTE_TYPE_ERROR,
    "AttributeTypeNotFoundError": ErrorCode.ATTRIBUTE_TYPE_NOT_FOUND,
    "EntityTypeAlreadyExistsError": ErrorCode.ENTITY_TYPE_ALREADY_EXISTS,
    "EntityTypeCantModifyError": ErrorCode.ENTITY_TYPE_CANT_MODIFY,
    "EntityTypeNotFoundError": ErrorCode.ENTITY_TYPE_NOT_FOUND,
    "EntityTypeTypeError": ErrorCode.ENTITY_TYPE_TYPE_ERROR,
    "ObjectClassAlreadyExistsError": ErrorCode.OBJECT_CLASS_ALREADY_EXISTS,
    "ObjectClassCantModifyError": ErrorCode.OBJECT_CLASS_CANT_MODIFY,
    "ObjectClassNotFoundError": ErrorCode.OBJECT_CLASS_NOT_FOUND,
    "ObjectClassTypeError": ErrorCode.OBJECT_CLASS_TYPE_ERROR,
    "MFAError": ErrorCode.MFA_ERROR,
    "MFAIdentityError": ErrorCode.MFA_IDENTITY_ERROR,
    "MFATokenError": ErrorCode.MFA_TOKEN_ERROR,
    "MissingMFACredentialsError": ErrorCode.MISSING_MFA_CREDENTIALS,
    "_MFAConnectError": ErrorCode.MFA_CONNECT_ERROR,
    "_MFAMissconfiguredError": ErrorCode.MFA_MISCONFIGURED,
    "_MultifactorError": ErrorCode.MULTIFACTOR_ERROR,
    "NetworkPolicyError": ErrorCode.NETWORK_POLICY_ERROR,
    "PasswordPolicyAlreadyExistsError": ErrorCode.PASSWORD_POLICY_ALREADY_EXISTS,  # noqa: E501
    "PasswordPolicyBaseError": ErrorCode.PASSWORD_POLICY_BASE_ERROR,
    "PasswordPolicyError": ErrorCode.PASSWORD_POLICY_ERROR,
    "PasswordPolicyNotFoundError": ErrorCode.PASSWORD_POLICY_NOT_FOUND,
    "AccessControlEntryAddError": ErrorCode.ACCESS_CONTROL_ENTRY_ADD,
    "AccessControlEntryNotFoundError": ErrorCode.ACCESS_CONTROL_ENTRY_NOT_FOUND,  # noqa: E501
    "AccessControlEntryUpdateError": ErrorCode.ACCESS_CONTROL_ENTRY_UPDATE,
    "RoleError": ErrorCode.ROLE_ERROR,
    "RoleNotFoundError": ErrorCode.ROLE_NOT_FOUND,
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

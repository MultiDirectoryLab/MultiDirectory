"""Password policy error utils.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import status
from fastapi_error_map.rules import rule

from api.error_routing import ERROR_MAP_TYPE, DomainErrorTranslator
from enums import DoaminCodes
from ldap_protocol.permissions_checker import AuthorizationError
from ldap_protocol.policies.password.exceptions import (
    PasswordBanWordWrongFileExtensionError,
    PasswordPolicyAgeDaysError,
    PasswordPolicyAlreadyExistsError,
    PasswordPolicyBaseDnNotFoundError,
    PasswordPolicyCantChangeDefaultDomainError,
    PasswordPolicyDirIsNotUserError,
    PasswordPolicyNotFoundError,
    PasswordPolicyPriorityError,
)

translator = DomainErrorTranslator(DoaminCodes.PASSWORD_POLICY)


error_map: ERROR_MAP_TYPE = {
    PasswordPolicyBaseDnNotFoundError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    PasswordPolicyNotFoundError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    PasswordPolicyDirIsNotUserError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    PasswordPolicyAlreadyExistsError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    PasswordPolicyCantChangeDefaultDomainError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    PasswordPolicyPriorityError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    PasswordPolicyAgeDaysError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    PasswordBanWordWrongFileExtensionError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    AuthorizationError: rule(
        status=status.HTTP_401_UNAUTHORIZED,
        translator=translator,
    ),
}

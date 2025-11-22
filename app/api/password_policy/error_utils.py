"""Password policy error utils.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi_error_map.rules import rule

from enums import ProjectPartCodes
from errors import ERROR_MAP_TYPE, BaseErrorTranslator, ErrorStatusCodes
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


class PasswordPolicyErrorTranslator(BaseErrorTranslator):
    """Password Policy error translator."""

    domain_code = ProjectPartCodes.PASSWORD_POLICY


error_map: ERROR_MAP_TYPE = {
    PasswordPolicyBaseDnNotFoundError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=PasswordPolicyErrorTranslator(),
    ),
    PasswordPolicyNotFoundError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=PasswordPolicyErrorTranslator(),
    ),
    PasswordPolicyDirIsNotUserError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=PasswordPolicyErrorTranslator(),
    ),
    PasswordPolicyAlreadyExistsError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=PasswordPolicyErrorTranslator(),
    ),
    PasswordPolicyCantChangeDefaultDomainError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=PasswordPolicyErrorTranslator(),
    ),
    PasswordPolicyPriorityError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=PasswordPolicyErrorTranslator(),
    ),
    PasswordPolicyAgeDaysError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=PasswordPolicyErrorTranslator(),
    ),
    PasswordBanWordWrongFileExtensionError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=PasswordPolicyErrorTranslator(),
    ),
}

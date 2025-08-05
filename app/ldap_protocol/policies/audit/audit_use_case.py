"""Audit use case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.asn1parser import LDAPOID
from ldap_protocol.objects import OperationEvent
from ldap_protocol.user_account_control import UserAccountControlFlag
from models import AuditSeverity

from .dataclasses import AuditPolicySetupDTO, AuditPolicyTriggerDTO
from .events.managers import RawAuditManager
from .policies_dao import AuditPoliciesDAO


class AuditUseCase:
    """Audit use case for handling audit policies."""

    def __init__(
        self,
        policy_dao: AuditPoliciesDAO,
        manager: RawAuditManager,
    ) -> None:
        """Initialize AuditUseCase."""
        self._policy_dao = policy_dao
        self._manager = manager

    async def check_event_processing_enabled(self, request_code: int) -> bool:
        """Check if event processing is enabled for a specific request code."""
        if request_code == OperationEvent.SEARCH:
            return False

        return await self._manager.get_processing_status()

    async def enable_event_processing(self) -> None:
        """Enable processing of audit events."""
        await self._manager.update_processing_status(True)

    async def disable_event_processing(self) -> None:
        """Disable processing of audit events."""
        await self._manager.update_processing_status(False)

    async def _create_standard_policies(
        self,
        object_class: str,
        is_success: bool,
    ) -> None:
        """Create standard create/modify/delete policies."""
        operations = {
            "create": OperationEvent.ADD,
            "modify": OperationEvent.MODIFY,
            "delete": OperationEvent.DELETE,
        }
        for action, operation_code in operations.items():
            await self._policy_dao.create_policy(
                AuditPolicySetupDTO(
                    object_class=object_class,
                    action=action,
                    is_success=is_success,
                    severity=AuditSeverity.INFO,
                ),
                [
                    AuditPolicyTriggerDTO(
                        is_ldap=True,
                        is_http=True,
                        operation_code=operation_code,
                        object_class=object_class,
                        is_operation_success=is_success,
                    ),
                ],
            )

    async def _create_password_modify_policy(
        self,
        object_class: str,
        is_success: bool,
    ) -> None:
        """Create password modify policy."""
        await self._policy_dao.create_policy(
            AuditPolicySetupDTO(
                object_class=object_class,
                action="password_modify",
                is_success=is_success,
                severity=AuditSeverity.INFO
                if is_success
                else AuditSeverity.WARNING,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    is_operation_success=is_success,
                    additional_info={
                        "change_attributes": [
                            "userpassword",
                            "unicodepwd",
                        ],
                    },
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.EXTENDED,
                    object_class=object_class,
                    is_operation_success=is_success,
                    additional_info={
                        "oid": LDAPOID.PASSWORD_MODIFY,
                    },
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=False,
                    is_http=True,
                    operation_code=OperationEvent.CHANGE_PASSWORD,
                    object_class=object_class,
                    is_operation_success=is_success,
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=False,
                    is_http=True,
                    operation_code=OperationEvent.CHANGE_PASSWORD_KERBEROS,
                    object_class=object_class,
                    is_operation_success=is_success,
                ),
            ],
        )

    async def _create_auth_policy(
        self,
        object_class: str,
        is_success: bool,
    ) -> None:
        """Create authentication policy."""
        await self._policy_dao.create_policy(
            AuditPolicySetupDTO(
                object_class=object_class,
                action="auth",
                is_success=is_success,
                severity=AuditSeverity.INFO
                if is_success
                else AuditSeverity.WARNING,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.BIND,
                    object_class=object_class,
                    is_operation_success=is_success,
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=False,
                    is_http=True,
                    operation_code=OperationEvent.AFTER_2FA,
                    object_class=object_class,
                    is_operation_success=is_success,
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=False,
                    is_http=True,
                    operation_code=OperationEvent.KERBEROS_AUTH,
                    object_class=object_class,
                    is_operation_success=is_success,
                ),
            ],
        )

    async def _create_reset_password_policy(
        self,
        object_class: str,
        is_success: bool,
    ) -> None:
        """Create reset password policy."""
        await self._policy_dao.create_policy(
            AuditPolicySetupDTO(
                object_class=object_class,
                action="reset_password",
                is_success=is_success,
                severity=AuditSeverity.INFO
                if is_success
                else AuditSeverity.WARNING,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    is_operation_success=is_success,
                    additional_info={
                        "change_attributes": ["useraccountcontrol"],
                        "operation": "&",
                        "value": UserAccountControlFlag.PASSWORD_EXPIRED,
                        "result": True,
                    },
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    is_operation_success=is_success,
                    additional_info={
                        "change_attributes": ["pwdlastset"],
                        "operation": "==",
                        "value": 0,
                        "result": True,
                    },
                ),
            ],
        )

    async def _create_user_specific_policies(
        self,
        is_success: bool,
        object_class: str = "user",
    ) -> None:
        """Create policies specific to user operations."""
        await self._create_password_modify_policy(object_class, is_success)
        await self._create_auth_policy(object_class, is_success)
        await self._create_reset_password_policy(object_class, is_success)

    async def _create_account_status_policies(
        self,
        object_class: str,
        is_success: bool,
    ) -> None:
        """Create policies for account status changes."""
        await self._policy_dao.create_policy(
            AuditPolicySetupDTO(
                object_class=object_class,
                action="enable",
                is_success=is_success,
                severity=AuditSeverity.INFO,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    is_operation_success=is_success,
                    additional_info={
                        "change_attributes": ["useraccountcontrol"],
                        "operation": "&",
                        "value": UserAccountControlFlag.ACCOUNTDISABLE,
                        "result": False,
                    },
                ),
            ],
        )
        await self._policy_dao.create_policy(
            AuditPolicySetupDTO(
                object_class=object_class,
                action="disable",
                is_success=is_success,
                severity=AuditSeverity.INFO,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    is_operation_success=is_success,
                    additional_info={
                        "change_attributes": ["useraccountcontrol"],
                        "operation": "&",
                        "value": UserAccountControlFlag.ACCOUNTDISABLE,
                        "result": True,
                    },
                ),
            ],
        )

    async def _create_group_member_policies(
        self,
        is_success: bool,
        object_class: str = "group",
    ) -> None:
        await self._policy_dao.create_policy(
            AuditPolicySetupDTO(
                object_class=object_class,
                action="add_member",
                is_success=is_success,
                severity=AuditSeverity.INFO,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    is_operation_success=is_success,
                    additional_info={
                        "change_attributes": ["member"],
                        "operation": "<",
                        "result": True,
                    },
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class="user",
                    is_operation_success=is_success,
                    additional_info={
                        "change_attributes": ["memberof"],
                        "operation": "<",
                        "result": True,
                    },
                ),
            ],
        )
        await self._policy_dao.create_policy(
            AuditPolicySetupDTO(
                object_class=object_class,
                action="remove_member",
                is_success=is_success,
                severity=AuditSeverity.INFO,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    is_operation_success=is_success,
                    additional_info={
                        "change_attributes": ["member"],
                        "operation": ">",
                        "result": True,
                    },
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class="user",
                    is_operation_success=is_success,
                    additional_info={
                        "change_attributes": ["memberof"],
                        "operation": ">",
                        "result": True,
                    },
                ),
            ],
        )

    async def _create_organizational_unit_policies(self) -> None:
        """Create policies for organizational units."""
        object_class = "organizationalUnit"
        await self._create_standard_policies(object_class, True)
        await self._create_standard_policies(object_class, False)

    async def _create_user_policies(self) -> None:
        """Create policies for user operations."""
        object_class = "user"
        await self._create_standard_policies(object_class, True)
        await self._create_user_specific_policies(True)
        await self._create_account_status_policies(object_class, True)
        await self._create_standard_policies(object_class, False)
        await self._create_user_specific_policies(False)
        await self._create_account_status_policies(object_class, False)

    async def _create_group_policies(self) -> None:
        """Create policies for group operations."""
        object_class = "group"
        await self._create_standard_policies(object_class, True)
        await self._create_group_member_policies(True)
        await self._create_standard_policies(object_class, False)
        await self._create_group_member_policies(False)

    async def _create_computer_policies(self) -> None:
        """Create policies for computer operations."""
        object_class = "computer"
        await self._create_standard_policies(object_class, True)
        await self._create_account_status_policies(object_class, True)
        await self._create_standard_policies(object_class, False)
        await self._create_account_status_policies(object_class, False)

    async def create_policies(self) -> None:
        """Create initial audit policies."""
        await self._create_organizational_unit_policies()
        await self._create_user_policies()
        await self._create_group_policies()
        await self._create_computer_policies()

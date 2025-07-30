"""Audit use case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.asn1parser import LDAPOID
from ldap_protocol.objects import OperationEvent
from ldap_protocol.user_account_control import UserAccountControlFlag
from models import AuditSeverity

from .dataclasses import AuditPolicyDTO, AuditPolicyTriggerDTO
from .policies_dao import AuditPoliciesDAO


class AuditUseCase:
    """Audit use case for handling audit policies."""

    def __init__(self, audit_dao: AuditPoliciesDAO) -> None:
        """Initialize AuditUseCase with a DAO instance.

        :param audit_dao: DAO instance for database operations.
        """
        self._audit_dao = audit_dao

    async def _create_standard_policies(
        self,
        object_class: str,
        line: str,
        is_ok: bool,
    ) -> None:
        """Create standard create/modify/delete policies."""
        operations = {
            "create": OperationEvent.ADD,
            "modify": OperationEvent.MODIFY,
            "delete": OperationEvent.DELETE,
        }
        for prefix, operation_code in operations.items():
            await self._audit_dao.create_policy(
                AuditPolicyDTO(
                    name=f"{prefix}_{object_class}_{line}",
                    severity=AuditSeverity.INFO,
                ),
                [
                    AuditPolicyTriggerDTO(
                        is_ldap=True,
                        is_http=True,
                        operation_code=operation_code,
                        object_class=object_class,
                        operation_success=is_ok,
                    )
                ],
            )

    async def _create_password_modify_policy(
        self,
        object_class: str,
        line: str,
        is_ok: bool,
    ) -> None:
        """Create password modify policy."""
        await self._audit_dao.create_policy(
            AuditPolicyDTO(
                name=f"password_modify_{object_class}_{line}",
                severity=AuditSeverity.INFO
                if is_ok
                else AuditSeverity.WARNING,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    operation_success=is_ok,
                    additional_info={
                        "change_attributes": [
                            "userpassword",
                            "unicodepwd",
                        ]
                    },
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.EXTENDED,
                    object_class=object_class,
                    operation_success=is_ok,
                    additional_info={
                        "oid": LDAPOID.PASSWORD_MODIFY,
                    },
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=False,
                    is_http=True,
                    operation_code=OperationEvent.CHANGE_PASSWORD,
                    object_class=object_class,
                    operation_success=is_ok,
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=False,
                    is_http=True,
                    operation_code=OperationEvent.CHANGE_PASSWORD_KERBEROS,
                    object_class=object_class,
                    operation_success=is_ok,
                ),
            ],
        )

    async def _create_auth_policy(
        self,
        object_class: str,
        line: str,
        is_ok: bool,
    ) -> None:
        """Create authentication policy."""
        await self._audit_dao.create_policy(
            AuditPolicyDTO(
                name=f"auth_{line}",
                severity=AuditSeverity.INFO
                if is_ok
                else AuditSeverity.WARNING,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.BIND,
                    object_class=object_class,
                    operation_success=is_ok,
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=False,
                    is_http=True,
                    operation_code=OperationEvent.AFTER_2FA,
                    object_class=object_class,
                    operation_success=is_ok,
                ),
                AuditPolicyTriggerDTO(
                    is_ldap=False,
                    is_http=True,
                    operation_code=OperationEvent.KERBEROS_AUTH,
                    object_class=object_class,
                    operation_success=is_ok,
                ),
            ],
        )

    async def _create_reset_password_policy(
        self,
        object_class: str,
        line: str,
        is_ok: bool,
    ) -> None:
        """Create reset password policy."""
        await self._audit_dao.create_policy(
            AuditPolicyDTO(
                name=f"reset_password_{object_class}_{line}",
                severity=AuditSeverity.INFO
                if is_ok
                else AuditSeverity.WARNING,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    operation_success=is_ok,
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
                    operation_success=is_ok,
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
        line: str,
        is_ok: bool,
        object_class: str = "user",
    ) -> None:
        """Create policies specific to user operations."""
        await self._create_password_modify_policy(object_class, line, is_ok)
        await self._create_auth_policy(object_class, line, is_ok)
        await self._create_reset_password_policy(object_class, line, is_ok)

    async def _create_account_status_policies(
        self,
        object_class: str,
        line: str,
        is_ok: bool,
    ) -> None:
        """Create policies for account status changes."""
        await self._audit_dao.create_policy(
            AuditPolicyDTO(
                name=f"enable_{object_class}_{line}",
                severity=AuditSeverity.INFO,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    operation_success=is_ok,
                    additional_info={
                        "change_attributes": ["useraccountcontrol"],
                        "operation": "&",
                        "value": UserAccountControlFlag.ACCOUNTDISABLE,
                        "result": False,
                    },
                )
            ],
        )
        await self._audit_dao.create_policy(
            AuditPolicyDTO(
                name=f"disable_{object_class}_{line}",
                severity=AuditSeverity.INFO,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    operation_success=is_ok,
                    additional_info={
                        "change_attributes": ["useraccountcontrol"],
                        "operation": "&",
                        "value": UserAccountControlFlag.ACCOUNTDISABLE,
                        "result": True,
                    },
                )
            ],
        )

    async def _create_group_member_policies(
        self,
        line: str,
        is_ok: bool,
        object_class: str = "group",
    ) -> None:
        await self._audit_dao.create_policy(
            AuditPolicyDTO(
                name=f"add_member_{object_class}_{line}",
                severity=AuditSeverity.INFO,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    operation_success=is_ok,
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
                    operation_success=is_ok,
                    additional_info={
                        "change_attributes": ["memberof"],
                        "operation": "<",
                        "result": True,
                    },
                ),
            ],
        )
        await self._audit_dao.create_policy(
            AuditPolicyDTO(
                name=f"remove_member_{object_class}_{line}",
                severity=AuditSeverity.INFO,
            ),
            [
                AuditPolicyTriggerDTO(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    operation_success=is_ok,
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
                    operation_success=is_ok,
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
        await self._create_standard_policies(object_class, "ok", True)
        await self._create_standard_policies(object_class, "fail", False)

    async def _create_user_policies(self) -> None:
        """Create policies for user operations."""
        object_class = "user"
        await self._create_standard_policies(object_class, "ok", True)
        await self._create_user_specific_policies("ok", True)
        await self._create_account_status_policies(object_class, "ok", True)
        await self._create_standard_policies(object_class, "fail", False)
        await self._create_user_specific_policies("fail", False)
        await self._create_account_status_policies(object_class, "fail", False)

    async def _create_group_policies(self) -> None:
        """Create policies for group operations."""
        object_class = "group"
        await self._create_standard_policies(object_class, "ok", True)
        await self._create_group_member_policies("ok", True)
        await self._create_standard_policies(object_class, "fail", False)
        await self._create_group_member_policies("fail", False)

    async def _create_computer_policies(self) -> None:
        """Create policies for computer operations."""
        object_class = "computer"
        await self._create_standard_policies(object_class, "ok", True)
        await self._create_account_status_policies(object_class, "ok", True)
        await self._create_standard_policies(object_class, "fail", False)
        await self._create_account_status_policies(object_class, "fail", False)

    async def create_policies(self) -> None:
        """Create initial audit policies."""
        await self._create_organizational_unit_policies()
        await self._create_user_policies()
        await self._create_group_policies()
        await self._create_computer_policies()

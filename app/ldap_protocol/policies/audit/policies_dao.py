"""Audit policies dao module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import LDAPOID
from ldap_protocol.objects import OperationEvent
from ldap_protocol.user_account_control import UserAccountControlFlag
from models import AuditPolicy, AuditPolicyTrigger, AuditSeverity


class AuditPoliciesDAO:
    """Audit DAO for managing audit policies."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Audit DAO with a database session."""
        self._session = session

    async def create_policy(
        self,
        policy: AuditPolicy,
        triggers: list[AuditPolicyTrigger],
    ) -> None:
        """Create a new audit policy."""
        for trigger in triggers:
            trigger.audit_policy = policy

        self._session.add_all([policy, *triggers])

    async def create_policies(self) -> None:
        """Create initial audit policies if they do not exist."""
        for object_class in {
            "organizationalUnit",
            "user",
            "group",
            "computer",
        }:
            for line, is_ok in {"ok": True, "fail": False}.items():
                await self.create_policy(
                    AuditPolicy(
                        name=f"create_{object_class}_{line}",
                        severity=AuditSeverity.INFO,
                    ),
                    [
                        AuditPolicyTrigger(
                            is_ldap=True,
                            is_http=True,
                            operation_code=OperationEvent.ADD,
                            object_class=object_class,
                            operation_success=is_ok,
                        )
                    ],
                )
                await self.create_policy(
                    AuditPolicy(
                        name=f"modify_{object_class}_{line}",
                        severity=AuditSeverity.INFO,
                    ),
                    [
                        AuditPolicyTrigger(
                            is_ldap=True,
                            is_http=True,
                            operation_code=OperationEvent.MODIFY,
                            object_class=object_class,
                            operation_success=is_ok,
                        )
                    ],
                )
                await self.create_policy(
                    AuditPolicy(
                        name=f"delete_{object_class}_{line}",
                        severity=AuditSeverity.INFO,
                    ),
                    [
                        AuditPolicyTrigger(
                            is_ldap=True,
                            is_http=True,
                            operation_code=OperationEvent.DELETE,
                            object_class=object_class,
                            operation_success=is_ok,
                        )
                    ],
                )

                if object_class == "user":
                    await self.create_policy(
                        AuditPolicy(
                            name=f"password_modify_{object_class}_{line}",
                            severity=AuditSeverity.INFO
                            if is_ok
                            else AuditSeverity.WARNING,
                        ),
                        [
                            AuditPolicyTrigger(
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
                            AuditPolicyTrigger(
                                is_ldap=True,
                                is_http=True,
                                operation_code=OperationEvent.EXTENDED,
                                object_class=object_class,
                                operation_success=is_ok,
                                additional_info={
                                    "oid": LDAPOID.PASSWORD_MODIFY,
                                },
                            ),
                            AuditPolicyTrigger(
                                is_ldap=False,
                                is_http=True,
                                operation_code=OperationEvent.CHANGE_PASSWORD,
                                object_class=object_class,
                                operation_success=is_ok,
                            ),
                            AuditPolicyTrigger(
                                is_ldap=False,
                                is_http=True,
                                operation_code=OperationEvent.CHANGE_PASSWORD_KERBEROS,
                                object_class=object_class,
                                operation_success=is_ok,
                            ),
                        ],
                    )
                    await self.create_policy(
                        AuditPolicy(
                            name=f"auth_{line}",
                            severity=AuditSeverity.INFO
                            if is_ok
                            else AuditSeverity.WARNING,
                        ),
                        [
                            AuditPolicyTrigger(
                                is_ldap=True,
                                is_http=True,
                                operation_code=OperationEvent.BIND,
                                object_class=object_class,
                                operation_success=is_ok,
                            ),
                            AuditPolicyTrigger(
                                is_ldap=False,
                                is_http=True,
                                operation_code=OperationEvent.AFTER_2FA,
                                object_class=object_class,
                                operation_success=is_ok,
                            ),
                            AuditPolicyTrigger(
                                is_ldap=False,
                                is_http=True,
                                operation_code=OperationEvent.KERBEROS_AUTH,
                                object_class=object_class,
                                operation_success=is_ok,
                            ),
                        ],
                    )
                    await self.create_policy(
                        AuditPolicy(
                            name=f"reset_password_{object_class}_{line}",
                            severity=AuditSeverity.INFO
                            if is_ok
                            else AuditSeverity.WARNING,
                        ),
                        [
                            AuditPolicyTrigger(
                                is_ldap=True,
                                is_http=True,
                                operation_code=OperationEvent.MODIFY,
                                object_class=object_class,
                                operation_success=is_ok,
                                additional_info={
                                    "change_attributes": [
                                        "useraccountcontrol"
                                    ],
                                    "operation": "&",
                                    "value": UserAccountControlFlag.PASSWORD_EXPIRED,  # noqa: E501
                                    "result": True,
                                },
                            ),
                            AuditPolicyTrigger(
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

                if object_class == "user" or object_class == "computer":
                    await self.create_policy(
                        AuditPolicy(
                            name=f"enable_{object_class}_{line}",
                            severity=AuditSeverity.INFO,
                        ),
                        [
                            AuditPolicyTrigger(
                                is_ldap=True,
                                is_http=True,
                                operation_code=OperationEvent.MODIFY,
                                object_class=object_class,
                                operation_success=is_ok,
                                additional_info={
                                    "change_attributes": [
                                        "useraccountcontrol"
                                    ],
                                    "operation": "&",
                                    "value": UserAccountControlFlag.ACCOUNTDISABLE,  # noqa: E501
                                    "result": False,
                                },
                            )
                        ],
                    )
                    await self.create_policy(
                        AuditPolicy(
                            name=f"disable_{object_class}_{line}",
                            severity=AuditSeverity.INFO,
                        ),
                        [
                            AuditPolicyTrigger(
                                is_ldap=True,
                                is_http=True,
                                operation_code=OperationEvent.MODIFY,
                                object_class=object_class,
                                operation_success=is_ok,
                                additional_info={
                                    "change_attributes": [
                                        "useraccountcontrol"
                                    ],
                                    "operation": "&",
                                    "value": UserAccountControlFlag.ACCOUNTDISABLE,  # noqa: E501
                                    "result": True,
                                },
                            )
                        ],
                    )

                if object_class == "group":
                    await self.create_policy(
                        AuditPolicy(
                            name=f"add_member_{object_class}_{line}",
                            severity=AuditSeverity.INFO,
                        ),
                        [
                            AuditPolicyTrigger(
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
                            AuditPolicyTrigger(
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
                    await self.create_policy(
                        AuditPolicy(
                            name=f"remove_member_{object_class}_{line}",
                            severity=AuditSeverity.INFO,
                        ),
                        [
                            AuditPolicyTrigger(
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
                            AuditPolicyTrigger(
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

        await self._session.flush()

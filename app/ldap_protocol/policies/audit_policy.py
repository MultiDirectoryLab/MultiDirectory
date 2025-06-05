"""Audit policies module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import json
import socket
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any

from fastapi import Request
from loguru import logger
from pydantic import BaseModel, Field, SecretStr
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import LDAPOID
from ldap_protocol.objects import OperationEvent
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.helpers import (
    get_ip_from_request,
    get_user_agent_from_request,
)
from models import AuditPolicy, AuditPolicyTrigger, AuditSeverity

if TYPE_CHECKING:
    from config import Settings
    from ldap_protocol.ldap_requests import BaseRequest
    from ldap_protocol.ldap_responses import BaseResponse


class AuditEvent(BaseModel):
    """Represent audit event with request, response and connection details."""

    request: dict[str, Any]
    responses: list[dict[str, Any]]
    protocol: str
    request_code: OperationEvent
    help_data: dict[str, Any]
    username: str
    source_ip: IPv4Address | IPv6Address
    dest_port: int = Field(..., gt=0, lt=65536)
    timestamp: float = Field(
        default_factory=lambda: datetime.now().timestamp()
    )
    hostname: str = Field(default_factory=socket.gethostname)
    is_success_request: bool | None = None

    @classmethod
    def from_redis(cls, redis_data: dict[bytes, bytes]) -> "AuditEvent":
        """Create AuditEvent instance from Redis dictionary data."""
        decoded_data = {
            key.decode(): value.decode() for key, value in redis_data.items()
        }

        parsed_data = {}
        for key, value in decoded_data.items():
            try:
                parsed_data[key] = json.loads(value)
            except json.JSONDecodeError:
                parsed_data[key] = value

        if "request_code" in parsed_data:
            parsed_data["request_code"] = OperationEvent(
                parsed_data["request_code"]
            )

        if "timestamp" in parsed_data:
            parsed_data["timestamp"] = float(parsed_data["timestamp"])
        if "dest_port" in parsed_data:
            parsed_data["dest_port"] = int(parsed_data["dest_port"])
        if "is_success_request" in parsed_data:
            parsed_data["is_success_request"] = (
                None
                if parsed_data["is_success_request"] == "None"
                else parsed_data["is_success_request"].lower() == "true"
            )

        return cls(**parsed_data)

    def _default_serializer(self, obj: Any) -> Any:
        """Convert various object types to serializable format."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, SecretStr):
            return "********"
        if isinstance(obj, bytes):
            return obj.decode(errors="replace")
        if hasattr(obj, "value"):
            return obj.value
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        try:
            return str(obj)
        except Exception:
            return "[unserializable]"

    def to_redis_message(self) -> dict[str, str]:
        """Transform AuditEvent into dictionary suitable for Redis storage."""
        data = self.model_dump()
        data["request_code"] = self.request_code.value
        return {
            key: json.dumps(value, default=self._default_serializer)
            if isinstance(value, dict) or isinstance(value, list)
            else str(value)
            for key, value in data.items()
        }


class AuditEventBuilder:
    """Builder for constructing AuditEvent objects from various request types.

    This class provides factory methods to create standardized audit events
    from different types of network requests (LDAP, HTTP etc.).
    """

    @classmethod
    def from_ldap_request(
        cls,
        request: "BaseRequest",
        responses: list["BaseResponse"],
        username: str,
        ip: IPv4Address | IPv6Address,
        help_data: dict[str, Any],
        settings: "Settings",
        protocol: str,
    ) -> AuditEvent:
        """Construct an AuditEvent from LDAP request data."""
        return AuditEvent(
            request=request.model_dump(),
            responses=[r.model_dump() for r in responses],
            protocol=protocol,
            request_code=request.PROTOCOL_OP,
            help_data=help_data,
            username=username,
            source_ip=ip,
            dest_port=settings.PORT,
        )

    @classmethod
    def from_http_request(
        cls,
        request: Request,
        event_type: OperationEvent,
        username: str,
        is_success_request: bool,
        settings: "Settings",
        target: str | None = None,
        error_code: int | None = None,
        error_message: str | None = None,
    ) -> AuditEvent:
        """Construct an AuditEvent from HTTP request data."""
        ip = get_ip_from_request(request)
        user_agent = get_user_agent_from_request(request)

        help_data: dict[str, dict[str, str | int]] = {
            "details": {
                "user-agent": user_agent,
            },
        }

        if event_type == OperationEvent.BIND:
            help_data["details"]["auth_choice"] = "API"

        if error_code:
            help_data["details"]["error_code"] = error_code
        if error_message:
            help_data["details"]["error_message"] = error_message
        if target:
            help_data["details"]["target"] = target

        return AuditEvent(
            request=dict(),
            responses=list(),
            protocol="API",
            request_code=event_type,
            help_data=help_data,
            username=username,
            source_ip=ip,
            dest_port=settings.HTTP_PORT,
            is_success_request=is_success_request,
        )


class RedisAuditDAO:
    """Implement Redis data access operations for audit event processing."""

    _client: Redis

    def __init__(self, redis: Redis) -> None:
        """Initialize Redis client for audit event operations."""
        self._client = redis

    async def is_event_processing_enabled(self, request_code: int) -> bool:
        """Check whether event processing is enabled for request type."""
        if request_code == OperationEvent.SEARCH:
            return False

        data = await self._client.get("is_proc_events")
        return data is not None and int(data) == 1

    async def enable_event_processing(self) -> None:
        """Enable processing of audit events in Redis."""
        await self._client.set("is_proc_events", 1)

    async def disable_event_processing(self) -> None:
        """Disable processing of audit events in Redis."""
        await self._client.set("is_proc_events", 0)

    async def add_audit_event(
        self, stream_name: str, event: "AuditEvent"
    ) -> None:
        """Add audit event to specified Redis stream."""
        await self._client.xadd(stream_name, event.to_redis_message())  # type: ignore

    async def create_consumer_group(
        self, stream_name: str, group_name: str, last_id: str = "0"
    ) -> None:
        """Create consumer group for reading events from Redis stream."""
        try:
            await self._client.xgroup_create(
                stream_name,
                group_name,
                last_id,
                mkstream=True,
            )
        except Exception as e:
            self._handle_group_creation_error(e, group_name)

    async def read_events(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        count: int = 10,
        block: int | None = None,
    ) -> list[tuple[str, list[tuple[str, dict[bytes, bytes]]]]]:
        """Read batch of events from Redis stream using consumer group."""
        return await self._client.xreadgroup(
            group_name,
            consumer_name,
            {stream_name: ">"},
            count=count,
            block=block,
        )

    async def acknowledge_and_delete_event(
        self, stream_name: str, group_name: str, event_id: str
    ) -> None:
        """Acknowledge event processing and remove it from Redis stream."""
        await self._client.xack(stream_name, group_name, event_id)
        await self._client.xdel(stream_name, event_id)

    def _handle_group_creation_error(
        self, error: Exception, group_name: str
    ) -> None:
        """Handle errors occurring during consumer group creation."""
        if "BUSYGROUP" in str(error):
            logger.critical(f"Consumer group {group_name} already exists.")
        else:
            raise error


async def add_audit_pocilies(session: AsyncSession) -> None:
    """Add audit policies."""
    for object_class in {"organizationalUnit", "user", "group", "computer"}:
        for line, is_ok in {"ok": True, "fail": False}.items():
            add_policy = AuditPolicy(
                name=f"create_{object_class}_{line}",
                severity=AuditSeverity.INFO,
            )
            add_trigger = AuditPolicyTrigger(
                is_ldap=True,
                is_http=True,
                operation_code=OperationEvent.ADD,
                object_class=object_class,
                operation_success=is_ok,
                audit_policy=add_policy,
            )
            session.add_all([add_policy, add_trigger])

            modify_policy = AuditPolicy(
                name=f"modify_{object_class}_{line}",
                severity=AuditSeverity.INFO,
            )
            modify_trigger = AuditPolicyTrigger(
                is_ldap=True,
                is_http=True,
                operation_code=OperationEvent.MODIFY,
                object_class=object_class,
                operation_success=is_ok,
                audit_policy=modify_policy,
            )
            session.add_all([modify_policy, modify_trigger])

            delete_policy = AuditPolicy(
                name=f"delete_{object_class}_{line}",
                severity=AuditSeverity.INFO,
            )
            delete_trigger = AuditPolicyTrigger(
                is_ldap=True,
                is_http=True,
                operation_code=OperationEvent.DELETE,
                object_class=object_class,
                operation_success=is_ok,
                audit_policy=delete_policy,
            )
            session.add_all([delete_policy, delete_trigger])

            if object_class == "user":
                policy = AuditPolicy(
                    name=f"password_modify_{object_class}_{line}",
                    severity=AuditSeverity.INFO
                    if is_ok
                    else AuditSeverity.WARNING,
                )
                trigger_1 = AuditPolicyTrigger(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.MODIFY,
                    object_class=object_class,
                    operation_success=is_ok,
                    additional_info={
                        "change_attributes": ["userpassword", "unicodepwd"]
                    },
                    audit_policy=policy,
                )
                trigger_2 = AuditPolicyTrigger(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.EXTENDED,
                    object_class=object_class,
                    operation_success=is_ok,
                    additional_info={"oid": LDAPOID.PASSWORD_MODIFY},
                    audit_policy=policy,
                )
                trigger_3 = AuditPolicyTrigger(
                    is_ldap=False,
                    is_http=True,
                    operation_code=OperationEvent.CHANGE_PASSWORD,
                    object_class=object_class,
                    operation_success=is_ok,
                    audit_policy=policy,
                )
                session.add_all([policy, trigger_1, trigger_2, trigger_3])

                policy = AuditPolicy(
                    name=f"auth_{line}",
                    severity=AuditSeverity.INFO
                    if is_ok
                    else AuditSeverity.WARNING,
                )
                trigger_1 = AuditPolicyTrigger(
                    is_ldap=True,
                    is_http=True,
                    operation_code=OperationEvent.BIND,
                    object_class=object_class,
                    operation_success=is_ok,
                    audit_policy=policy,
                )
                trigger_2 = AuditPolicyTrigger(
                    is_ldap=False,
                    is_http=True,
                    operation_code=OperationEvent.AFTER_2FA,
                    object_class=object_class,
                    operation_success=is_ok,
                    audit_policy=policy,
                )
                session.add_all([policy, trigger_1, trigger_2])

                policy = AuditPolicy(
                    name=f"reset_password_{object_class}_{line}",
                    severity=AuditSeverity.INFO
                    if is_ok
                    else AuditSeverity.WARNING,
                )
                trigger_1 = AuditPolicyTrigger(
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
                    audit_policy=policy,
                )
                trigger_2 = AuditPolicyTrigger(
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
                    audit_policy=policy,
                )
                session.add_all([policy, trigger_1, trigger_2])

            if object_class == "user" or object_class == "computer":
                policy = AuditPolicy(
                    name=f"enable_{object_class}_{line}",
                    severity=AuditSeverity.INFO,
                )
                trigger = AuditPolicyTrigger(
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
                    audit_policy=policy,
                )
                session.add_all([policy, trigger])

                policy = AuditPolicy(
                    name=f"disable_{object_class}_{line}",
                    severity=AuditSeverity.INFO,
                )
                trigger = AuditPolicyTrigger(
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
                    audit_policy=policy,
                )
                session.add_all([policy, trigger])

            if object_class == "group":
                policy = AuditPolicy(
                    name=f"add_member_{object_class}_{line}",
                    severity=AuditSeverity.INFO,
                )
                trigger_1 = AuditPolicyTrigger(
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
                    audit_policy=policy,
                )
                trigger_2 = AuditPolicyTrigger(
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
                    audit_policy=policy,
                )
                session.add_all([policy, trigger_1, trigger_2])

                policy = AuditPolicy(
                    name=f"remove_member_{object_class}_{line}",
                    severity=AuditSeverity.INFO,
                )
                trigger_1 = AuditPolicyTrigger(
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
                    audit_policy=policy,
                )
                trigger_2 = AuditPolicyTrigger(
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
                    audit_policy=policy,
                )
                session.add_all([policy, trigger_1, trigger_2])

    await session.flush()

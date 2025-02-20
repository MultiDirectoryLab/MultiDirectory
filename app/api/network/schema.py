"""Network models.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import sys
from ipaddress import IPv4Address, IPv4Network, summarize_address_range
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)

from ldap_protocol.utils.helpers import validate_entry
from models import MFAFlags


class IPRange(BaseModel):
    """Range of ips."""

    start: IPv4Address
    end: IPv4Address


IPv4IntefaceListType = list[IPv4Address | IPv4Network | IPRange]


class NetmasksMixin:
    """Netmasks comuted value container."""

    netmasks: IPv4IntefaceListType

    @computed_field  # type: ignore
    @property
    def complete_netmasks(self) -> list[IPv4Address | IPv4Network]:
        """Validate range or return networks range."""
        values = []
        for item in self.netmasks:
            if isinstance(item, IPRange):
                values.extend(
                    list(summarize_address_range(item.start, item.end)),
                )
            else:
                values.append(IPv4Network(item))
        return values  # type: ignore

    @field_validator("groups")
    @classmethod
    def validate_group(cls, groups: list[str]) -> list[str]:
        if not groups:
            return groups
        if all(validate_entry(group) for group in groups):
            return groups

        raise ValueError("Invalid DN")

    @field_validator("mfa_groups")
    @classmethod
    def validate_mfa_group(cls, mfa_groups: list[str]) -> list[str]:
        if not mfa_groups:
            return mfa_groups
        if all(validate_entry(group) for group in mfa_groups):
            return mfa_groups

        raise ValueError("Invalid DN")

    @field_serializer("netmasks")
    @classmethod
    def netmasks_serialize(
        cls, netmasks: IPv4IntefaceListType,
    ) -> list[str | dict]:
        """Serialize netmasks to list.

        :param IPv4IntefaceListType netmasks: ip masks
        :return list[str | dict]: ready to json serialized
        """
        values: list[str | dict] = []

        for netmask in netmasks:
            if isinstance(netmask, IPRange):
                values.append(
                    {"start": str(netmask.start), "end": str(netmask.end)},
                )
            else:
                values.append(str(netmask))

        return values


class Policy(BaseModel, NetmasksMixin):
    """Network Policy model."""

    name: str = Field(examples=["local network"], max_length=100)
    netmasks: IPv4IntefaceListType = Field(examples=[["172.0.0.0/8"]])
    priority: int = Field(ge=1, le=sys.maxsize, examples=[2])
    groups: list[str] = []
    mfa_status: MFAFlags = MFAFlags.DISABLED
    mfa_groups: list[str] = []
    is_http: bool
    is_ldap: bool
    is_kerberos: bool
    bypass_no_connection: bool
    bypass_service_failure: bool
    ldap_session_ttl: int
    http_session_ttl: int


class PolicyResponse(BaseModel):
    """Network Policy model for response."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    netmasks: list[IPv4Network]
    raw: list[str | dict]
    priority: int = Field(ge=1, le=sys.maxsize, examples=[2])
    enabled: bool
    groups: list[str] = []
    mfa_status: MFAFlags
    mfa_groups: list[str] = []
    is_http: bool
    is_ldap: bool
    is_kerberos: bool
    bypass_no_connection: bool
    bypass_service_failure: bool
    ldap_session_ttl: int
    http_session_ttl: int


class PolicyUpdate(BaseModel, NetmasksMixin):
    """Update request."""

    id: int
    name: str | None = None
    netmasks: IPv4IntefaceListType | None = None  # type: ignore
    groups: list[str] | None = None
    mfa_status: MFAFlags | None = None
    mfa_groups: list[str] | None = None
    is_http: bool | None = None
    is_ldap: bool | None = None
    is_kerberos: bool | None = None
    bypass_no_connection: bool | None = None
    bypass_service_failure: bool | None = None
    ldap_session_ttl: int | None = None
    http_session_ttl: int | None = None

    @model_validator(mode="after")
    def check_passwords_match(self) -> Self:
        """Validate if all fields are empty."""
        if not self.name and not self.netmasks and not self.groups:
            raise ValueError("Name, netmasks and group cannot be empty")

        return self


class SwapRequest(BaseModel):
    """Swap priority values."""

    first_policy_id: int
    second_policy_id: int


class SwapResponse(BaseModel):
    """Swap priority values."""

    first_policy_id: int
    first_policy_priority: int = Field(ge=1, le=sys.maxsize, examples=[2])
    second_policy_id: int
    second_policy_priority: int = Field(ge=1, le=sys.maxsize, examples=[2])

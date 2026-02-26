"""MultiDirectory LDAP entities.

(imperative mapping + dataclasses, SQLAlchemy 2.0).
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from typing import ClassVar, Literal

from enums import (
    AceType,
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
    AuditSeverity,
    AuthorizationRules,
    MFAFlags,
    RoleScope,
)

type DistinguishedNamePrefix = Literal["cn", "ou", "dc"]


@dataclass
class CatalogueSetting:
    """Catalogue setting key/value pair stored in Settings table."""

    id: int | None = field(init=False, default=None)
    name: str = ""
    value: str = ""


@dataclass
class EntityType:
    """Entity type grouping object classes; assigned to directories."""

    id: int | None = field(init=False, default=None)
    name: str = ""
    object_class_names: list[str] = field(default_factory=list)
    is_system: bool = False
    directories: list[Directory] = field(
        init=False,
        default_factory=list,
        repr=False,
    )

    @property
    def object_class_names_set(self) -> set[str]:
        return set(self.object_class_names)


@dataclass
class PasswordPolicy:
    """Password Policy configuration.

    `priority` - lower number means higher priority.
    """

    id: int = field(init=False)
    priority: int

    name: str
    language: str

    is_exact_match: bool
    history_length: int

    min_age_days: int
    max_age_days: int

    min_length: int
    max_length: int

    min_lowercase_letters_count: int
    min_uppercase_letters_count: int

    min_special_symbols_count: int
    min_digits_count: int
    min_unique_symbols_count: int
    max_repeating_symbols_in_row_count: int

    max_sequential_keyboard_symbols_count: int
    max_sequential_alphabet_symbols_count: int

    max_failed_attempts: int
    failed_attempts_reset_sec: int
    lockout_duration_sec: int
    fail_delay_sec: int

    groups: list[Group] = field(default_factory=list, repr=False)


@dataclass
class Directory:
    """Directory (LDAP entry) node in hierarchy with attributes."""

    id: int = field(init=False)
    name: str
    is_system: bool = field(default=False)
    object_sid: str = field(default="")
    object_guid: uuid.UUID = field(default_factory=uuid.uuid4)
    parent_id: int | None = None
    entity_type_id: int | None = None
    object_class: str = ""
    rdname: str = ""
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    updated_at: datetime | None = field(default=None)
    depth: int = field(default=0)
    path: list[str] = field(default_factory=list)

    parent: Directory | None = field(default=None, repr=False, compare=False)
    entity_type: EntityType | None = field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )
    attributes: list[Attribute] = field(
        init=False,
        default_factory=list,
        repr=False,
        compare=False,
    )
    group: Group = field(init=False, repr=False, compare=False)
    user: User | None = field(init=False, repr=False, compare=False)
    groups: list[Group] = field(init=False, repr=False, compare=False)
    access_control_entries: list[AccessControlEntry] = field(
        init=False,
        default_factory=list,
        repr=False,
        compare=False,
    )

    search_fields: ClassVar[dict[str, str]] = {
        "name": "name",
        "objectguid": "objectGUID",
    }
    ro_fields: ClassVar[set[str]] = {
        "uid",
        "whencreated",
        "lastlogon",
        "authtimestamp",
        "objectguid",
        "objectsid",
        "entitytypename",
        "name",
    }

    def get_dn_prefix(self) -> DistinguishedNamePrefix:
        return {
            "organizationalUnit": "ou",
            "domain": "dc",
            "container": "cn",
        }.get(
            self.object_class,
            "cn",
        )  # type: ignore

    def get_dn(self, dn: str = "cn") -> str:
        return f"{dn}={self.name}"

    @property
    def is_domain(self) -> bool:
        return not self.parent_id and self.object_class == "domain"

    @property
    def path_dn(self) -> str:
        return ",".join(reversed(self.path))

    def create_path(
        self,
        parent: Directory | None = None,
        dn: str = "cn",
    ) -> None:
        pre = parent.path if parent else []
        self.path = pre + [self.get_dn(dn)]
        self.depth = len(self.path)
        self.rdname = dn

    @property
    def relative_id(self) -> str:
        """Get RID from objectSid attribute.

        Relative Identifier (RID) is the last sub-authority value of a SID.
        """
        attrs = self.__dict__.get("attributes")
        if not attrs:
            return ""

        for attr in attrs:
            if attr.name and attr.name.lower() == "objectsid" and attr.value:
                return attr.value.split("-")[-1]
        return ""

    @property
    def attributes_dict(self) -> defaultdict[str, list[str]]:
        d: defaultdict[str, list[str]] = defaultdict(list)
        for attr in self.attributes:
            d[attr.name].extend(attr.values)
        return d

    @property
    def object_class_names_set(self) -> set[str]:
        return set(
            self.attributes_dict.get("objectClass", [])
            + self.attributes_dict.get("objectclass", []),
        )

    @property
    def entity_type_object_class_names_set(self) -> set[str]:
        return (
            self.entity_type.object_class_names_set
            if self.entity_type
            else set()
        )


@dataclass
class Attribute:
    """Single attribute (string or binary) attached to a Directory entry."""

    id: int = field(init=False)
    directory_id: int
    name: str
    value: str | None = None
    bvalue: bytes | None = None
    directory: Directory = field(init=False, repr=False)

    @property
    def _decoded_value(self) -> str | None:
        if self.value:
            return self.value
        if self.bvalue:
            return self.bvalue.decode("latin-1")
        return None

    @property
    def values(self) -> list[str]:
        return [self._decoded_value] if self._decoded_value else []


@dataclass
class User:
    """User account (directory entry specialization)."""

    id: int = field(init=False)
    directory_id: int = field()
    directory: Directory = field(repr=False, init=False)
    sam_account_name: str
    user_principal_name: str
    mail: str | None = None
    display_name: str | None = None
    password: str | None = None
    last_logon: datetime | None = None
    account_exp: datetime | None = None
    password_history: list[str] = field(default_factory=list)

    samaccountname: str = field(init=False)
    userprincipalname: str = field(init=False)
    displayname: str = field(init=False)
    uid: str = field(init=False)
    accountexpires: datetime | None = field(init=False)

    groups: list[Group] = field(default_factory=list, repr=False)

    search_fields: ClassVar[dict[str, str]] = {
        "mail": "mail",
        "samaccountname": "sAMAccountName",
        "userprincipalname": "userPrincipalName",
        "displayname": "displayName",
        "uid": "uid",
        "accountexpires": "accountExpires",
    }
    fields: ClassVar[dict[str, str]] = {
        "loginshell": "loginShell",
        "uidnumber": "uidNumber",
        "homedirectory": "homeDirectory",
    }

    def is_expired(self) -> bool:
        if self.account_exp is None:
            return False
        now = datetime.now(tz=timezone.utc)
        user_account_exp = self.account_exp.astimezone(timezone.utc)
        return now > user_account_exp


@dataclass
class Group:
    """Group object referencing directory entry; manages memberships."""

    id: int = field(init=False)
    directory_id: int = field()
    directory: Directory = field(
        init=False,
        repr=False,
        compare=False,
    )
    members: list[Directory] = field(
        init=False,
        default_factory=list,
        repr=False,
        compare=False,
    )
    parent_groups: list[Group] = field(
        init=False,
        default_factory=list,
        repr=False,
        compare=False,
    )
    policies: list[NetworkPolicy] = field(
        init=False,
        default_factory=list,
        repr=False,
        compare=False,
    )
    mfa_policies: list[NetworkPolicy] = field(
        init=False,
        default_factory=list,
        repr=False,
        compare=False,
    )
    users: list[User] = field(
        init=False,
        default_factory=list,
        repr=False,
        compare=False,
    )
    roles: list[Role] = field(
        init=False,
        default_factory=list,
        repr=False,
        compare=False,
    )
    password_policies: list[PasswordPolicy] = field(
        init=False,
        default_factory=list,
        repr=False,
        compare=False,
    )
    search_fields: ClassVar[dict[str, str]] = {}


@dataclass
class Role:
    """Authorization role aggregating ACEs and group assignments."""

    id: int = field(init=False)
    name: str = ""
    creator_upn: str | None = None
    is_system: bool = False
    created_at: datetime = field(init=False, repr=False)
    groups: list[Group] = field(default_factory=list, repr=False)
    access_control_entries: list[AccessControlEntry] = field(
        default_factory=list,
        repr=False,
    )
    permissions: AuthorizationRules = AuthorizationRules(0)


@dataclass
class AccessControlEntry:
    """Access Control Entry defining permission & scope constraints."""

    id: int = field(init=False)
    ace_type: AceType
    scope: RoleScope
    role_id: int | None = None
    depth: int | None = None
    path: str = ""
    attribute_type_name: str | None = None
    entity_type_id: int | None = None
    is_allow: bool = False

    role: Role | None = field(init=False, default=None, repr=False)
    entity_type: EntityType | None = field(
        init=False,
        default=None,
        repr=False,
    )
    directories: list[Directory] = field(
        default_factory=list,
        repr=False,
    )

    @property
    def entity_type_name(self) -> str | None:
        return self.entity_type.name if self.entity_type else None


@dataclass
class NetworkPolicy:
    """Network access policy (netmasks, protocol enable flags, MFA)."""

    id: int = field(init=False)
    name: str = ""
    raw: dict | list = field(default_factory=dict)
    netmasks: list[IPv4Network | IPv4Address] = field(default_factory=list)
    enabled: bool = True
    priority: int = 0
    mfa_status: MFAFlags = MFAFlags.DISABLED
    is_ldap: bool = True
    is_http: bool = True
    is_kerberos: bool = True
    bypass_no_connection: bool = False
    bypass_service_failure: bool = False
    ldap_session_ttl: int = 7200
    http_session_ttl: int = 28800
    groups: list[Group] = field(init=False, default_factory=list, repr=False)
    mfa_groups: list[Group] = field(
        init=False,
        default_factory=list,
        repr=False,
    )


@dataclass
class AuditPolicyTrigger:
    """Trigger describing auditable operation conditions."""

    id: int | None = field(init=False, default=None)
    audit_policy_id: int = field(init=False)
    audit_policy: AuditPolicy = field(repr=False, init=False)
    is_ldap: bool = True
    is_http: bool = True
    operation_code: int = 0
    object_class: str = ""
    additional_info: dict | None = None
    is_operation_success: bool = True


@dataclass
class AuditPolicy:
    """Audit policy grouping triggers with severity & enabled flag."""

    id: int = field(init=False)
    severity: AuditSeverity
    name: str = ""
    is_enabled: bool = False
    triggers: list[AuditPolicyTrigger] = field(
        init=False,
        default_factory=list,
        repr=False,
    )


@dataclass
class AuditDestination:
    """Destination for audit events (service/protocol/host/port)."""

    id: int | None = field(init=False, default=None)
    name: str
    service_type: AuditDestinationServiceType
    protocol: AuditDestinationProtocolType
    is_enabled: bool = True
    host: str = ""
    port: int = 0


@dataclass
class PasswordBanWord:
    """List of banned password words."""

    word: str


@dataclass
class DedicatedServer:
    """Dedicated server."""

    id: int = field(init=False)
    name: str
    host: str
    port: int
    username: str
    password: str
    base_dn: str
    domain_name: str
    use_tls: bool
    bind_type: Literal["SIMPLE", "GSSAPI"]

"""Search protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import sys
from collections import defaultdict
from functools import cached_property
from math import ceil
from typing import Any, AsyncGenerator, ClassVar

from loguru import logger
from pydantic import Field, PrivateAttr, field_serializer
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload, with_loader_criteria
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression
from sqlalchemy.sql.expression import Select

from config import Settings
from entities import (
    Attribute,
    AttributeType,
    Directory,
    Group,
    ObjectClass,
    User,
)
from enums import AceType
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.filter_interpreter import (
    FilterInterpreterProtocol,
    LDAPFilterInterpreter,
)
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    PartialAttribute,
    SearchResultDone,
    SearchResultEntry,
    SearchResultReference,
)
from ldap_protocol.objects import DerefAliases, ProtocolRequests, Scope
from ldap_protocol.roles.access_manager import AccessManager
from ldap_protocol.utils.cte import get_all_parent_group_directories
from ldap_protocol.utils.helpers import (
    dt_to_ft,
    get_generalized_now,
    get_windows_timestamp,
    string_to_sid,
)
from ldap_protocol.utils.queries import (
    dn_is_base_directory,
    get_base_directories,
    get_path_filter,
    get_search_path,
)
from repo.pg.tables import queryable_attr as qa

from .base import BaseRequest
from .contexts import LDAPSearchRequestContext

_attrs = ["tokengroups", "memberof", "member"]
_attrs.extend(User.search_fields.keys())
_attrs.extend(Directory.search_fields.keys())
_ATTRS_TO_CLEAN = set(_attrs)

_filtered_dir_search_fields = set(Directory.search_fields) - {
    "objectsid",
    "objectguid",
}


class SearchRequest(BaseRequest):
    """Search request schema.

    ```
    SearchRequest ::= [APPLICATION 3] SEQUENCE {
        baseObject      LDAPDN,
        scope           ENUMERATED {
            baseObject              (0),
            singleLevel             (1),
            wholeSubtree            (2),
            subordinateSubtree      (3),
        },
        derefAliases    ENUMERATED {
            neverDerefAliases       (0),
            derefInSearching        (1),
            derefFindingBaseObj     (2),
            derefAlways             (3)
        },
        sizeLimit       INTEGER (0 ..  maxInt),
        timeLimit       INTEGER (0 ..  maxInt),
        typesOnly       BOOLEAN,
        filter          Filter,
        attributes      AttributeSelection
    }
    ```
    """

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.SEARCH

    base_object: str = Field("", description="Any `DistinguishedName`")
    scope: Scope
    deref_aliases: DerefAliases
    size_limit: int = Field(ge=0, le=sys.maxsize, examples=[1000])
    time_limit: int = Field(ge=0, le=sys.maxsize, examples=[1000])
    types_only: bool
    filter: ASN1Row = Field(...)
    attributes: list[str]

    page_number: int | None = Field(None, ge=1, examples=[1])  # only json API

    _filter_interpreter: FilterInterpreterProtocol = PrivateAttr(
        default_factory=LDAPFilterInterpreter,
    )

    class Config:
        """Allow class to use property."""

        arbitrary_types_allowed = True
        ignored_types = (cached_property,)

    @field_serializer("filter")
    def serialize_filter(self, val: ASN1Row | None, _info: Any) -> str | None:
        """Serialize filter field."""
        return val.to_ldap_filter() if isinstance(val, ASN1Row) else None

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> "SearchRequest":
        (
            base_object,
            scope,
            deref_aliases,
            size_limit,
            time_limit,
            types_only,
            filter_,
            attributes,
        ) = data[:8]  # type: ignore

        return cls(
            base_object=base_object.value,
            scope=int(scope.value),
            deref_aliases=int(deref_aliases.value),
            size_limit=size_limit.value,
            time_limit=time_limit.value,
            types_only=types_only.value,
            filter=filter_,
            attributes=[field.value for field in attributes.value],
        )

    @cached_property
    def requested_attrs(self) -> list[str]:
        return [attr.lower() for attr in self.attributes]

    async def _get_subschema(self, session: AsyncSession) -> SearchResultEntry:
        attrs: dict[str, list[str]] = defaultdict(list)

        attrs["name"].append("Schema")
        attrs["objectClass"].append("subSchema")
        attrs["objectClass"].append("top")

        attribute_types = await session.scalars(select(AttributeType))
        attrs["attributeTypes"] = [
            attribute_type.get_raw_definition()
            for attribute_type in attribute_types
        ]

        object_classes = await session.scalars(
            select(ObjectClass).options(
                selectinload(qa(ObjectClass.attribute_types_must)),
                selectinload(qa(ObjectClass.attribute_types_may)),
            ),
        )
        attrs["objectClasses"] = [
            object_class.get_raw_definition()
            for object_class in object_classes
        ]

        return SearchResultEntry(
            object_name="CN=Schema",
            partial_attributes=[
                PartialAttribute(type=key, vals=value)
                for key, value in attrs.items()
            ],
        )

    async def get_root_dse(
        self,
        session: AsyncSession,
        settings: Settings,
    ) -> defaultdict[str, list[str]]:
        """Get RootDSE.

        :return defaultdict[str, list[str]]: queried attrs
        """
        data = defaultdict(list)
        domain_query = select(Directory).filter_by(object_class="domain")
        domain = (await session.scalars(domain_query)).one()

        schema = "CN=Schema"
        if self.requested_attrs == ["subschemasubentry"]:
            data["subschemaSubentry"].append(schema)
            return data

        data["dnsHostName"].append(domain.name)
        data["serverName"].append(domain.name)
        data["serviceName"].append(domain.name)
        data["dsServiceName"].append(domain.name)
        data["LDAPServiceName"].append(domain.name)
        data["vendorName"].append(settings.VENDOR_NAME)
        data["vendorVersion"].append(settings.VENDOR_VERSION)
        data["namingContexts"].append(domain.path_dn)
        data["namingContexts"].append(schema)
        data["rootDomainNamingContext"].append(domain.path_dn)
        data["supportedLDAPVersion"].append("3")
        data["defaultNamingContext"].append(domain.path_dn)
        data["currentTime"].append(get_generalized_now(settings.TIMEZONE))
        data["subschemaSubentry"].append(schema)
        data["schemaNamingContext"].append(schema)
        data["supportedSASLMechanisms"] = [
            "ANONYMOUS",
            "PLAIN",
            "GSSAPI",
            "GSS-SPNEGO",
        ]
        data["highestCommittedUSN"].append("126991")
        data["supportedExtension"] = [
            "1.3.6.1.4.1.4203.1.11.3",  # whoami
            "1.3.6.1.4.1.4203.1.11.1",  # password modify
        ]
        data["supportedControl"] = [
            "2.16.840.1.113730.3.4.4",  # password expire policy
        ]
        data["domainFunctionality"].append("0")
        data["supportedLDAPPolicies"] = [
            "MaxConnIdleTime",
            "MaxPageSize",
            "MaxValRange",
        ]
        data["supportedCapabilities"] = [
            "1.2.840.113556.1.4.800",  # ACTIVE_DIRECTORY_OID
            "1.2.840.113556.1.4.1670",  # ACTIVE_DIRECTORY_V51_OID
            "1.2.840.113556.1.4.1791",  # ACTIVE_DIRECTORY_LDAP_INTEG_OID
        ]

        return data

    def cast_filter(self) -> UnaryExpression | ColumnElement:
        """Convert asn1 row filter_ to sqlalchemy obj.

        :param ASN1Row filter_: requested filter_
        :param AsyncSession session: sa session
        :return UnaryExpression: condition
        """
        return self._filter_interpreter.cast_to_sql(self.filter)

    async def handle(
        self,
        ctx: LDAPSearchRequestContext,
    ) -> AsyncGenerator[
        SearchResultDone | SearchResultReference | SearchResultEntry,
        None,
    ]:
        """Search tree.

        Provides following responses:
        Entry -> Reference (optional) -> Done
        """
        async for response in self.get_result(ctx):
            yield response

    async def get_result(
        self,
        ctx: LDAPSearchRequestContext,
    ) -> AsyncGenerator[SearchResultEntry | SearchResultDone, None]:
        """Create response.

        :param bool user_logged: is user in session
        :param AsyncSession session: sa session
        :yield SearchResult: search result
        """
        is_root_dse = self.scope == Scope.BASE_OBJECT and not self.base_object
        is_schema = self.base_object.lower() == "cn=schema"
        user = ctx.ldap_session.user

        if not (is_root_dse or is_schema) and user is None:
            yield SearchResultDone(**INVALID_ACCESS_RESPONSE)
            return

        if self.scope == Scope.BASE_OBJECT and (is_root_dse or is_schema):
            if is_schema:
                yield await self._get_subschema(ctx.session)
            elif is_root_dse:
                attrs = await self.get_root_dse(ctx.session, ctx.settings)
                yield SearchResultEntry(
                    object_name="",
                    partial_attributes=[
                        PartialAttribute(type=name, vals=values)
                        for name, values in attrs.items()
                    ],
                )
            yield SearchResultDone(result_code=LDAPCodes.SUCCESS)
            return

        if not user:
            yield SearchResultDone(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
            return

        query = self.build_query(
            await get_base_directories(ctx.session),
            user,
            ctx.access_manager,
        )

        try:
            cond = self.cast_filter()
            query = query.filter(cond)
        except Exception as err:
            logger.exception("Error occurred while filtering query")
            logger.error(f"Filter syntax error {err}, {type(err)}")
            yield SearchResultDone(result_code=LDAPCodes.PROTOCOL_ERROR)
            return

        query, pages_total, count = await self.paginate_query(
            query,
            ctx.session,
        )

        if self.size_limit != 0:
            query = query.limit(self.size_limit)

        async for response in self.tree_view(
            query,
            ctx.session,
            user,
            ctx.access_manager,
        ):
            yield response

        yield SearchResultDone(
            result_code=LDAPCodes.SUCCESS,
            total_pages=pages_total,
            total_objects=count,
        )

    @cached_property
    def member_of(self) -> bool:
        return "memberof" in self.requested_attrs or self.all_attrs

    @cached_property
    def entity_type_name(self) -> bool:
        return "entitytypename" in self.requested_attrs or self.all_attrs

    @cached_property
    def member(self) -> bool:
        return "member" in self.requested_attrs or self.all_attrs

    @cached_property
    def token_groups(self) -> bool:
        return "tokengroups" in self.requested_attrs

    @property
    def is_sid_requested(self) -> bool:
        return self.all_attrs or "objectsid" in self.requested_attrs

    @property
    def is_guid_requested(self) -> bool:
        return self.all_attrs or "objectguid" in self.requested_attrs

    @cached_property
    def all_attrs(self) -> bool:
        return "*" in self.requested_attrs or not self.requested_attrs

    def _mutate_query_with_attributes_to_load(
        self,
        query: Select,
    ) -> Select:
        """Get attributes to load."""
        if self.entity_type_name:
            query = (
                query.join(qa(Directory.entity_type))
                .options(selectinload(qa(Directory.entity_type)))
            )  # fmt: skip

        if self.all_attrs:
            return query.options(selectinload(qa(Directory.attributes)))

        attrs = [
            attr
            for attr in self.requested_attrs
            if attr not in _ATTRS_TO_CLEAN
        ]

        return query.options(
            selectinload(qa(Directory.attributes)),
            with_loader_criteria(
                Attribute,
                func.lower(Attribute.name).in_(attrs),
            ),
        )

    def build_query(
        self,
        base_directories: list[Directory],
        user: UserSchema,
        access_manager: AccessManager,
    ) -> Select:
        """Build tree query."""
        query = (
            select(Directory)
            .join(qa(Directory.user), isouter=True)
            .options(joinedload(qa(Directory.user)))
            .options(selectinload(qa(Directory.group)))
        )

        query = self._mutate_query_with_attributes_to_load(query)
        query = access_manager.mutate_query_with_ace_load(
            user_role_ids=user.role_ids,
            query=query,
            ace_types=[AceType.READ],
            load_attribute_type=True,
        )

        for base_directory in base_directories:
            if dn_is_base_directory(base_directory, self.base_object):
                root_is_base = True
                break
        else:
            root_is_base = False

        search_path = get_search_path(self.base_object)

        if self.scope == Scope.BASE_OBJECT:
            if self.base_object:
                query = query.filter(get_path_filter(search_path))
            else:
                query = query.filter(
                    or_(
                        *[
                            get_path_filter(domain.path)
                            for domain in base_directories
                            if domain.path is not None
                        ],
                    ),
                )

        elif self.scope == Scope.SINGLE_LEVEL:
            query = query.filter(
                qa(Directory.depth) == len(search_path) + 1,
                get_path_filter(
                    column=qa(Directory.path)[1 : len(search_path)],
                    path=search_path,
                ),
            )

        elif self.scope == Scope.WHOLE_SUBTREE and not root_is_base:
            query = query.filter(
                get_path_filter(
                    column=qa(Directory.path)[1 : len(search_path)],
                    path=search_path,
                ),
            )

        if self.member:
            query = query.options(
                selectinload(qa(Directory.group)).selectinload(
                    qa(Group.members),
                ),
            )

        if self.member_of or self.token_groups:
            query = query.options(
                selectinload(qa(Directory.groups)).joinedload(
                    qa(Group.directory),
                ),
            )

        return query

    async def paginate_query(
        self,
        query: Select,
        session: AsyncSession,
    ) -> tuple[Select, int, int]:
        """Paginate query.

        :param _type_ query: _description_
        :param _type_ session: _description_
        :return tuple[select, int, int]: query, pages_total, count
        """
        if self.page_number is None:
            return query, 0, 0

        count_q = select(func.count()).select_from(query.subquery())

        count = (await session.scalars(count_q)).one()

        start = (self.page_number - 1) * self.size_limit
        query = query.offset(start).limit(self.size_limit)

        return query, int(ceil(count / float(self.size_limit))), count

    async def _fill_attrs(
        self,
        directory: Directory,
        obj_classes: list[str],
        distinguished_name: str,
        attrs: dict[str, list[str]],
        session: AsyncSession,
    ) -> None:
        if "distinguishedname" not in self.requested_attrs or self.all_attrs:
            attrs["distinguishedName"].append(distinguished_name)

        if "whenCreated" in self.requested_attrs or self.all_attrs:
            attrs["whenCreated"].append(
                directory.created_at.strftime("%Y%m%d%H%M%S.0Z"),
            )

        if directory.user:
            if "accountexpires" in self.requested_attrs or self.all_attrs:
                if directory.user.account_exp is None:
                    attrs["accountExpires"].append("0")
                else:
                    attrs["accountExpires"].append(
                        str(dt_to_ft(directory.user.account_exp)),
                    )

            if (
                "lastlogon" in self.requested_attrs
                or "authTimestamp" in self.requested_attrs
                or self.all_attrs
            ):
                if directory.user.last_logon is None:
                    attrs["lastLogon"].append("0")
                else:
                    attrs["lastLogon"].append(
                        str(get_windows_timestamp(directory.user.last_logon)),
                    )
                    attrs["authTimestamp"].append(
                        directory.user.last_logon.isoformat(),
                    )

        if self.member_of:
            logger.debug(f"Member of group: {directory.groups}")
            for group in directory.groups:
                attrs["memberOf"].append(group.directory.path_dn)

        if self.token_groups and "user" in obj_classes:
            attrs["tokenGroups"].append(
                str(string_to_sid(directory.object_sid)),
            )

            group_directories = await get_all_parent_group_directories(
                directory.groups,
                session,
            )

            if group_directories is not None:
                async for directory_ in group_directories:
                    attrs["tokenGroups"].append(
                        str(string_to_sid(directory_.object_sid)),
                    )

        if self.member and "group" in obj_classes and directory.group:
            for member in directory.group.members:
                attrs["member"].append(member.path_dn)

    @staticmethod
    def get_directory_sid(directory: Directory) -> bytes:
        return string_to_sid(directory.object_sid)

    @staticmethod
    def get_directory_guid(directory: Directory) -> bytes:
        return directory.object_guid.bytes_le

    async def tree_view(  # noqa: C901
        self,
        query: Select,
        session: AsyncSession,
        user: UserSchema,
        access_manager: AccessManager,
    ) -> AsyncGenerator[SearchResultEntry, None]:
        """Yield all resulted directories."""
        directories = await session.stream_scalars(query)

        async for directory in directories:
            attrs = defaultdict(list)
            obj_classes = []

            can_read, forbidden_attributes, allowed_attributes = (
                access_manager.check_search_access(
                    directory=directory,
                    user_dn=user.dn,
                )
            )

            if not can_read:
                continue

            if not access_manager.check_search_filter_attrs(
                self._filter_interpreter.attributes,
                forbidden_attributes,
                allowed_attributes,
            ):
                continue

            for attr in directory.attributes:
                if isinstance(attr.value, str):
                    value = attr.value.replace("\\x00", "\x00")
                else:
                    value = attr.bvalue

                if attr.name.lower() == "objectclass":
                    obj_classes.append(value)

                attrs[attr.name].append(value)

            distinguished_name = directory.path_dn

            await self._fill_attrs(
                directory,
                obj_classes,
                distinguished_name,
                attrs,
                session,
            )

            if directory.user:
                if self.all_attrs:
                    user_fields = directory.user.search_fields.keys()
                else:
                    user_fields = (
                        attr
                        for attr in self.requested_attrs
                        if (
                            directory.user
                            and (attr in directory.user.search_fields)
                        )
                    )
            else:
                user_fields = []

            if directory.group:
                if self.all_attrs:
                    group_fields = directory.group.search_fields.keys()
                else:
                    group_fields = (
                        attr
                        for attr in self.requested_attrs
                        if (
                            directory.group
                            and (attr in directory.group.search_fields)
                        )
                    )
            else:
                group_fields = []

            for attr in group_fields:
                attribute = getattr(directory.group, attr)
                attrs[directory.group.search_fields[attr]].append(attribute)

            for attr in user_fields:
                if attr == "accountexpires":
                    continue
                attribute = getattr(directory.user, attr)
                attrs[directory.user.search_fields[attr]].append(attribute)

            if self.all_attrs:
                directory_fields = _filtered_dir_search_fields
            else:
                directory_fields = {
                    attr
                    for attr in self.requested_attrs
                    if attr in _filtered_dir_search_fields
                }

            for attr in directory_fields:
                attribute = getattr(directory, attr)
                attrs[directory.search_fields[attr]].append(attribute)

            if self.is_guid_requested:
                guid = self.get_directory_guid(directory)
                attrs[directory.search_fields["objectguid"]].append(guid)  # type: ignore

            if self.is_sid_requested:
                guid = self.get_directory_sid(directory)
                attrs[directory.search_fields["objectsid"]].append(guid)  # type: ignore

            if self.entity_type_name:
                attrs["entityTypeName"].append(directory.entity_type.name)

            for attr_name in list(attrs):
                attr_name_lower = attr_name.lower()
                if (
                    forbidden_attributes
                    and attr_name_lower in forbidden_attributes
                ) or (
                    allowed_attributes
                    and attr_name_lower not in allowed_attributes
                ):
                    del attrs[attr_name]

            yield SearchResultEntry(
                object_name=distinguished_name,
                partial_attributes=[
                    PartialAttribute(type=key, vals=value)
                    for key, value in attrs.items()
                ],
            )

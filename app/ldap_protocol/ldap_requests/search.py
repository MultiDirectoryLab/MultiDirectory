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
from pydantic import Field, field_serializer
from sqlalchemy import func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import defaultload, joinedload, subqueryload
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression
from sqlalchemy.sql.expression import Select

from config import Settings
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.filter_interpreter import cast_filter2sql
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    PartialAttribute,
    SearchResultDone,
    SearchResultEntry,
    SearchResultReference,
)
from ldap_protocol.ldap_schema.object_class_crud import (
    get_object_classes_by_names,
)
from ldap_protocol.objects import DerefAliases, Scope
from ldap_protocol.policies.access_policy import mutate_ap
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
from models import AttributeType, Directory, Group, ObjectClass, User

from .base import BaseRequest


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

    PROTOCOL_OP: ClassVar[int] = 3

    base_object: str = Field("", description="Any `DistinguishedName`")
    scope: Scope
    deref_aliases: DerefAliases
    size_limit: int = Field(ge=0, le=sys.maxsize, examples=[1000])
    time_limit: int = Field(ge=0, le=sys.maxsize, examples=[1000])
    types_only: bool
    filter: ASN1Row = Field(...)
    attributes: list[str]

    page_number: int | None = Field(None, ge=1, examples=[1])  # only json API

    class Config:
        """Allow class to use property."""

        arbitrary_types_allowed = True
        ignored_types = (cached_property,)

    @field_serializer("filter")
    def serialize_filter(self, val: ASN1Row | None, _info: Any) -> str | None:
        """Serialize filter field."""
        return val.to_ldap_filter() if isinstance(val, ASN1Row) else None

    @classmethod
    def from_data(
        cls,
        data: dict[str, list[ASN1Row]],
    ) -> "SearchRequest":
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

        object_classes = await session.scalars(select(ObjectClass))
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
        domain_query = (
            select(Directory)
            .where(Directory.object_class == "domain")
        )  # fmt: skip
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
        data["supportedSASLMechanisms"] = ["ANONYMOUS", "PLAIN", "GSSAPI"]
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
        return cast_filter2sql(self.filter)

    async def handle(
        self,
        session: AsyncSession,
        ldap_session: LDAPSession,
        settings: Settings,
    ) -> AsyncGenerator[
        SearchResultDone | SearchResultReference | SearchResultEntry,
        None,
    ]:
        """Search tree.

        Provides following responses:
        Entry -> Reference (optional) -> Done
        """
        async with ldap_session.lock() as user:
            async for response in self.get_result(user, session, settings):
                yield response

    async def get_result(
        self,
        user: UserSchema | None,
        session: AsyncSession,
        settings: Settings,
    ) -> AsyncGenerator[SearchResultEntry | SearchResultDone, None]:
        """Create response.

        :param bool user_logged: is user in session
        :param AsyncSession session: sa session
        :yield SearchResult: search result
        """
        is_root_dse = self.scope == Scope.BASE_OBJECT and not self.base_object
        is_schema = self.base_object.lower() == "cn=schema"

        if not (is_root_dse or is_schema) and user is None:
            yield SearchResultDone(**INVALID_ACCESS_RESPONSE)
            return

        if self.scope == Scope.BASE_OBJECT and (is_root_dse or is_schema):
            if is_schema:
                yield await self._get_subschema(session)
            elif is_root_dse:
                attrs = await self.get_root_dse(session, settings)
                yield SearchResultEntry(
                    object_name="",
                    partial_attributes=[
                        PartialAttribute(type=name, vals=values)
                        for name, values in attrs.items()
                    ],
                )
            yield SearchResultDone(result_code=LDAPCodes.SUCCESS)
            return

        query = self.build_query(await get_base_directories(session), user)  # type: ignore

        try:
            cond = self.cast_filter()
            query = query.filter(cond)
        except Exception as err:
            logger.error(f"Filter syntax error {err}")
            yield SearchResultDone(result_code=LDAPCodes.PROTOCOL_ERROR)
            return

        query, pages_total, count = await self.paginate_query(query, session)

        async for response in self._tree_view(query, session):
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
    def member(self) -> bool:
        return "member" in self.requested_attrs or self.all_attrs

    @cached_property
    def token_groups(self) -> bool:
        return "tokengroups" in self.requested_attrs

    @cached_property
    def all_attrs(self) -> bool:
        return "*" in self.requested_attrs or not self.requested_attrs

    def build_query(
        self,
        base_directories: list[Directory],
        user: UserSchema,
    ) -> Select:
        """Build tree query."""
        query = (
            select(Directory)
            .join(User, isouter=True)
            .join(Directory.attributes, isouter=True)
            .options(
                subqueryload(Directory.attributes),
                joinedload(Directory.user),
                joinedload(Directory.group),
            )
            .distinct(Directory.id)
        )

        query = mutate_ap(query, user)

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
                func.cardinality(Directory.path) == len(search_path) + 1,
                get_path_filter(
                    column=Directory.path[0 : len(search_path)],
                    path=search_path,
                ),
            )

        elif self.scope == Scope.WHOLE_SUBTREE and not root_is_base:
            query = query.filter(
                get_path_filter(
                    column=Directory.path[1 : len(search_path)],
                    path=search_path,
                ),
            )

        if self.member:
            query = query.options(
                defaultload(Directory.group).selectinload(Group.members)
            )

        if self.member_of or self.token_groups:
            query = query.options(
                defaultload(Directory.groups).joinedload(Group.directory)
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
        end = start + self.size_limit
        query = query.offset(start).limit(end)

        return query, int(ceil(count / float(self.size_limit))), count

    async def _tree_view(
        self,
        query: Select,
        session: AsyncSession,
    ) -> AsyncGenerator[SearchResultEntry, None]:
        """Yield all resulted directories."""
        directories = await session.stream_scalars(query)

        async for directory in directories:
            attrs = await self._display_directory(session, directory)

            yield SearchResultEntry(
                object_name=directory.path_dn,
                partial_attributes=[
                    PartialAttribute(type=key, vals=value)
                    for key, value in attrs.items()
                ],
            )

    async def _display_directory(  # noqa: C901
        self,
        session: AsyncSession,
        directory: Directory,
    ) -> dict:
        """Display directory."""
        # object_classes
        object_classes = []
        for d_attribute in directory.attributes:
            if d_attribute.name.lower() == "objectclass":
                if isinstance(d_attribute.value, str):
                    oc_value = d_attribute.value.replace("\\x00", "\x00")
                else:
                    oc_value = d_attribute.bvalue  # type: ignore

                object_classes.append(oc_value)

        attrs = defaultdict(list)

        # default attrs
        attrs["distinguishedName"].append(directory.path_dn)
        attrs["whenCreated"].append(
            directory.created_at.strftime("%Y%m%d%H%M%S.0Z"),
        )

        # base attrs
        for d_attribute in directory.attributes:
            d_key = d_attribute.name

            if isinstance(d_attribute.value, str):
                d_value = d_attribute.value.replace("\\x00", "\x00")
            else:
                d_value = d_attribute.bvalue  # type: ignore

            attrs[d_key].append(d_value)

        # memberOf
        if (
            self.member_of
            and (
                "group" in object_classes
                or "user" in object_classes
            )
        ):  # fmt: skip
            # values
            for group in directory.groups:
                attrs["memberOf"].append(group.directory.path_dn)

        # tokenGroups
        if self.token_groups and "user" in object_classes:
            # base values
            attrs["tokenGroups"].append(
                str(string_to_sid(directory.object_sid))
            )

            # values
            group_directories = await get_all_parent_group_directories(
                directory.groups,
                session,
            )
            if group_directories is not None:
                async for directory_ in group_directories:
                    attrs["tokenGroups"].append(
                        str(string_to_sid(directory_.object_sid))
                    )

        # member
        if self.member and "group" in object_classes and directory.group:
            for member in directory.group.members:
                attrs["member"].append(member.path_dn)

        # user_fields
        if directory.user:
            # names
            user_field_names: list = []
            if self.all_attrs:
                user_field_names = list(directory.user.search_fields.keys())
            else:
                user_field_names = [
                    requested_attr_name
                    for requested_attr_name in self.requested_attrs
                    if (
                        directory.user
                        and (
                            requested_attr_name in directory.user.search_fields
                        )
                    )
                ]

            # values
            for user_field_name in user_field_names:
                if user_field_name == "accountexpires":
                    continue

                u_key = directory.user.search_fields[user_field_name]
                u_value = getattr(directory.user, user_field_name)
                attrs[u_key].append(u_value)

            # default values
            if directory.user.account_exp is None:
                attrs["accountExpires"].append("0")
            else:
                attrs["accountExpires"].append(
                    str(dt_to_ft(directory.user.account_exp))
                )

            if directory.user.last_logon is None:
                attrs["lastLogon"].append("0")
            else:
                attrs["lastLogon"].append(
                    str(get_windows_timestamp(directory.user.last_logon))
                )
                attrs["authTimestamp"].append(str(directory.user.last_logon))

        # group_fields
        if directory.group:
            # names
            group_field_names = []
            if self.all_attrs:
                group_field_names = list(directory.group.search_fields.keys())
            else:
                group_field_names = [
                    requested_attr
                    for requested_attr in self.requested_attrs
                    if (
                        directory.group
                        and (requested_attr in directory.group.search_fields)
                    )
                ]

            # values
            for group_field_name in group_field_names:
                g_key = directory.group.search_fields[group_field_name]
                g_value = getattr(directory.group, group_field_name)
                attrs[g_key].append(g_value)

        # directory_fields
        if directory.search_fields:
            # names
            directory_field_names: list[str] = []

            if self.all_attrs:
                directory_field_names = list(directory.search_fields.keys())
            else:
                directory_field_names = list(
                    requested_attr
                    for requested_attr in self.requested_attrs
                    if requested_attr in directory.search_fields
                )

            # values
            for dir_field_name in directory_field_names:
                d_field_key = directory.search_fields[dir_field_name]

                d_field_value = getattr(directory, dir_field_name)
                if dir_field_name == "objectsid":
                    d_field_value = string_to_sid(d_field_value)
                elif dir_field_name == "objectguid":
                    d_field_value = d_field_value.bytes_le

                attrs[d_field_key].append(d_field_value)

        # slice attrs
        allowed_attrs = set()
        for object_class in await get_object_classes_by_names(
            object_classes,
            session,
        ):
            allowed_attrs.update(object_class.attribute_types_may_display)
            allowed_attrs.update(object_class.attribute_types_must_display)

        # ответ
        return {k: v for k, v in attrs.items() if k in allowed_attrs}

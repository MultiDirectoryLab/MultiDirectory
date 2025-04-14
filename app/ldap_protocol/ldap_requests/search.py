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
from ldap_protocol.ldap_schema.flat_ldap_schema import (
    get_attribute_type_names_by_object_class_names,
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

        query, pages_total, count = await self._paginate_query(query, session)

        async for ldap_tree_entry in self._get_ldap_tree_entries(
            query,
            session,
        ):
            yield ldap_tree_entry

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

    async def _paginate_query(
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

    async def _get_ldap_tree_entries(
        self,
        query: Select,
        session: AsyncSession,
    ) -> AsyncGenerator[SearchResultEntry, None]:
        """Yield all resulted directories."""
        directories = await session.stream_scalars(query)

        async for directory in directories:
            # Apply LDAP Schema START
            # Apply LDAP Schema START
            # Apply LDAP Schema START
            # Apply LDAP Schema START
            # 1, 3
            object_class_names = set()
            for attribute in directory.attributes:
                if attribute.name.lower() == "objectclass":
                    if attribute.value:
                        field_value = attribute.value
                    elif attribute.bvalue:
                        field_value = attribute.bvalue.decode()
                    object_class_names.add(field_value)

            # 2
            if not object_class_names:
                await session.rollback()
                return

            pipeline = CollectLdapTreeEntryPipeline(
                directory,
                object_class_names,
                session,
                search_request=self,
            )

            unfiltered_fields = await pipeline.get_unfiltered_fields()

            # 6
            (
                _ldap_schema_must_field_names,
                _ldap_schema_may_field_names,
            ) = await get_attribute_type_names_by_object_class_names(
                session,
                object_class_names,
            )

            # 6 lower
            ldap_schema_must_field_names = {
                field_name.lower()
                for field_name in _ldap_schema_must_field_names
            }
            ldap_schema_may_field_names = {
                field_name.lower()
                for field_name in _ldap_schema_may_field_names
            }

            # 7
            attributes_must: dict[str, Any] = {}
            attributes_may: dict[str, Any] = {}
            attributes_dropped: dict[str, Any] = {}
            # must_field_names_used: set[str] = set()
            for name, values in unfiltered_fields.items():
                if name.lower() in ldap_schema_must_field_names:
                    attributes_must[name] = values
                    # must_field_names_used.add(name.lower())
                    if not values:
                        message = f"Attribute {name} must have a value"
                        logger.warning(message)
                        # FIXME Это возможно тоже не нужно в SearchRequest
                        # yield AddResponse(
                        #     result_code=LDAPCodes.OBJECT_CLASS_VIOLATION,
                        #     message=message,
                        # )
                elif name.lower() in ldap_schema_may_field_names:
                    attributes_may[name] = values
                else:
                    attributes_dropped[name] = values

            # DO NOT USE IT
            # FIXME Это возможно тоже не нужно в SearchRequest
            # if attributes_dropped:
            #     message = f"Attributes {attributes_dropped} are not allowed"
            #     logger.warning(message)
            #     yield AddResponse(
            #         result_code=LDAPCodes.NO_SUCH_ATTRIBUTE,
            #         message=message,
            #     )
            # DO NOT USE IT

            # DO NOT USE IT
            # FIXME Это не нужно в SearchRequest
            # if len(must_field_names_used) != len(ldap_schema_must_field_names):
            #     message = (
            #         f"ENTRY: pipeline"
            #         f"Object class must have all required attributes. "
            #         f"Expected: {ldap_schema_must_field_names}, "
            #         f"Got: {must_field_names_used}"
            #     )
            #     logger.warning(message)
            #     yield AddResponse(
            #         result_code=LDAPCodes.INVALID_ATTRIBUTE_SYNTAX,
            #         message=message,
            #     )
            # DO NOT USE IT

            fields_filtered = {
                **attributes_must,
                **attributes_may,
            }
            # Apply LDAP Schema END
            # Apply LDAP Schema END
            # Apply LDAP Schema END
            # Apply LDAP Schema END

            yield SearchResultEntry(
                object_name=directory.path_dn,
                partial_attributes=[
                    PartialAttribute(type=key, vals=value)
                    for key, value in fields_filtered.items()
                ],
            )


class CollectLdapTreeEntryPipeline:
    """Collect Entry for LDAP tree according to the LDAP schema."""

    def __init__(
        self,
        directory: Directory,
        object_class_names: set[str],
        session: AsyncSession,
        search_request: SearchRequest,
    ) -> None:
        """Init pipeline.

        :param Directory directory: it's the skeleton of the future entry
        :param AsyncSession session: session
        :param SearchRequest search_request: search request
        """
        self._session = session
        self._directory = directory
        self._search_request = search_request

        self._object_class_names: set[str] = object_class_names
        self._fields_unfiltered: dict[str, list] = defaultdict(list)
        self._fields_filtered: dict[str, list] = defaultdict(list)

        self._is_finished: bool = False

    async def get_unfiltered_fields(self) -> dict[str, list]:
        self._fields_unfiltered["distinguishedName"].append(
            self._directory.path_dn
        )
        self._fields_unfiltered["whenCreated"].append(
            self._directory.created_at.strftime("%Y%m%d%H%M%S.0Z"),
        )

        if self._directory.attributes:
            self._pick_around_directory_attributes()

        if self._need_expand_attr_memberof():
            self._expand_attr_memberof()

        if self._need_expand_attr_token_groups():
            await self._expand_attr_token_groups()

        if self._need_expand_attr_member():
            self._expand_attr_member()

        if self._directory.user:
            self._pick_around_user_fields()

        if self._directory.group:
            self._pick_around_group_fields()

        if self._directory.search_fields:
            self._pick_around_directory_search_fields()

        return self._fields_unfiltered

    def _expand_attr_memberof(self) -> None:
        for group in self._directory.groups:
            self._fields_unfiltered["memberOf"].append(group.directory.path_dn)

    def _need_expand_attr_memberof(self) -> bool:
        return bool(
            self._search_request.member_of
            and (
                "group" in self._object_class_names
                or "user" in self._object_class_names
            )
        )

    def _pick_around_directory_search_fields(self) -> None:
        directory_field_names: list[str] = []

        if self._search_request.all_attrs:
            directory_field_names = list(self._directory.search_fields.keys())
        else:
            directory_field_names = list(
                requested_attr
                for requested_attr in self._search_request.requested_attrs
                if requested_attr in self._directory.search_fields
            )

        for dir_field_name in directory_field_names:
            field_name = self._directory.search_fields[dir_field_name]

            field_value = getattr(self._directory, dir_field_name)
            if dir_field_name == "objectsid":
                field_value = string_to_sid(field_value)
            elif dir_field_name == "objectguid":
                field_value = field_value.bytes_le

            self._fields_unfiltered[field_name].append(field_value)

    def _pick_around_group_fields(self) -> None:
        group_field_names = []
        if self._search_request.all_attrs:
            group_field_names = list(
                self._directory.group.search_fields.keys()
            )
        else:
            group_field_names = [
                requested_attr
                for requested_attr in self._search_request.requested_attrs
                if (
                    self._directory.group
                    and (requested_attr in self._directory.group.search_fields)
                )
            ]

        for group_field_name in group_field_names:
            field_name = self._directory.group.search_fields[group_field_name]
            field_value = getattr(self._directory.group, group_field_name)
            self._fields_unfiltered[field_name].append(field_value)

    def _pick_around_user_fields(self) -> None:
        user_field_names: list = []
        if self._search_request.all_attrs:
            user_field_names = list(self._directory.user.search_fields.keys())
        else:
            user_field_names = [
                requested_attr_name
                for requested_attr_name in self._search_request.requested_attrs
                if (
                    self._directory.user
                    and (
                        requested_attr_name
                        in self._directory.user.search_fields
                    )
                )
            ]

        for user_field_name in user_field_names:
            if user_field_name == "accountexpires":
                continue

            field_name = self._directory.user.search_fields[user_field_name]
            field_value = getattr(self._directory.user, user_field_name)
            self._fields_unfiltered[field_name].append(field_value)

        if self._directory.user.account_exp is None:
            self._fields_unfiltered["accountExpires"].append("0")
        else:
            self._fields_unfiltered["accountExpires"].append(
                str(dt_to_ft(self._directory.user.account_exp))
            )

        if self._directory.user.last_logon is None:
            self._fields_unfiltered["lastLogon"].append("0")
        else:
            self._fields_unfiltered["lastLogon"].append(
                str(get_windows_timestamp(self._directory.user.last_logon))
            )
            self._fields_unfiltered["authTimestamp"].append(
                str(self._directory.user.last_logon)
            )

    def _expand_attr_member(self) -> None:
        for member in self._directory.group.members:
            self._fields_unfiltered["member"].append(member.path_dn)

    def _need_expand_attr_member(self) -> bool:
        return bool(
            self._search_request.member
            and "group" in self._object_class_names
            and self._directory.group
        )  # fmt: skip

    async def _expand_attr_token_groups(self) -> None:
        self._fields_unfiltered["tokenGroups"].append(
            str(string_to_sid(self._directory.object_sid))
        )

        group_directories = await get_all_parent_group_directories(
            self._directory.groups,
            self._session,
        )
        if group_directories is not None:
            async for group_directory in group_directories:
                self._fields_unfiltered["tokenGroups"].append(
                    str(string_to_sid(group_directory.object_sid))
                )

    def _need_expand_attr_token_groups(self) -> bool:
        return (
            self._search_request.token_groups
            and "user" in self._object_class_names
        )

    def _pick_around_directory_attributes(self) -> dict:
        for attribute in self._directory.attributes:
            field_name = attribute.name

            if isinstance(attribute.value, str):
                field_value = attribute.value.replace("\\x00", "\x00")
            else:
                field_value = attribute.bvalue  # type: ignore

            self._fields_unfiltered[field_name].append(field_value)
        return self._fields_unfiltered

"""Search protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import sys
from collections import defaultdict
from functools import cached_property
from math import ceil
from typing import AsyncGenerator, ClassVar

from loguru import logger
from pydantic import Field
from sqlalchemy import func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import joinedload, selectinload, subqueryload
from sqlalchemy.sql.elements import UnaryExpression
from sqlalchemy.sql.expression import Select

from config import VENDOR_NAME, VENDOR_VERSION, Settings
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, LDAPSession
from ldap_protocol.filter_interpreter import cast_filter2sql
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    PartialAttribute,
    SearchResultDone,
    SearchResultEntry,
    SearchResultReference,
)
from ldap_protocol.objects import DerefAliases, Scope
from ldap_protocol.utils import (
    dn_is_base_directory,
    dt_to_ft,
    get_attribute_types,
    get_base_directories,
    get_generalized_now,
    get_object_classes,
    get_path_filter,
    get_search_path,
    get_windows_timestamp,
    string_to_sid,
)
from models.ldap3 import Directory, Group, Path, User

from .base import BaseRequest

ATTRIBUTE_TYPES = get_attribute_types()
OBJECT_CLASSES = get_object_classes()


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

    base_object: str = Field('', description='Any `DistinguishedName`')
    scope: Scope
    deref_aliases: DerefAliases
    size_limit: int = Field(ge=0, le=sys.maxsize, examples=[1000])
    time_limit: int = Field(ge=0, le=sys.maxsize, examples=[1000])
    types_only: bool
    filter: ASN1Row = Field(...)  # noqa: A003
    attributes: list[str]

    page_number: int | None = Field(None, ge=1, examples=[1])  # only json API

    class Config:
        """Allow class to use property."""

        arbitrary_types_allowed = True
        ignored_types = (cached_property,)
        json_encoder = {
            ASN1Row: lambda value: str(value),
        }

    @classmethod
    def from_data(   # noqa: D102
            cls, data: dict[str, list[ASN1Row]]) -> 'SearchRequest':
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
    def requested_attrs(self) -> list[str]:  # noqa
        return [attr.lower() for attr in self.attributes]

    def _get_subschema(self) -> SearchResultEntry:
        attrs = defaultdict(list)
        attrs['name'].append('Schema')
        attrs['objectClass'].append('subSchema')
        attrs['objectClass'].append('top')

        attrs['attributeTypes'] = ATTRIBUTE_TYPES
        attrs['objectClasses'] = OBJECT_CLASSES

        return SearchResultEntry(
            object_name='CN=Schema',
            partial_attributes=[
                PartialAttribute(type=key, vals=value)
                for key, value in attrs.items()])

    async def get_root_dse(
            self, session: AsyncSession,
            settings: Settings) -> defaultdict[str, list[str]]:
        """Get RootDSE.

        :return defaultdict[str, list[str]]: queried attrs
        """
        data = defaultdict(list)
        domain = await session.scalar(select(Directory).where(
            Directory.object_class == 'domain'))

        schema = 'CN=Schema'
        if self.requested_attrs == ['subschemasubentry']:
            data['subschemaSubentry'].append(schema)
            return data

        data['dnsHostName'].append(domain.name)
        data['serverName'].append(domain.name)
        data['serviceName'].append(domain.name)
        data['dsServiceName'].append(domain.name)
        data['LDAPServiceName'].append(domain.name)
        data['vendorName'].append(VENDOR_NAME)
        data['vendorVersion'].append(VENDOR_VERSION)
        data['namingContexts'].append(domain.path_dn)
        data['namingContexts'].append(schema)
        data['rootDomainNamingContext'].append(domain.path_dn)
        data['supportedLDAPVersion'].append('3')
        data['defaultNamingContext'].append(domain.path_dn)
        data['currentTime'].append(get_generalized_now(settings.TIMEZONE))
        data['subschemaSubentry'].append(schema)
        data['schemaNamingContext'].append(schema)
        data['supportedSASLMechanisms'] = ['ANONYMOUS', 'PLAIN']
        data['highestCommittedUSN'].append('126991')
        data['supportedExtension'] = [
            "1.3.6.1.4.1.4203.1.11.3",  # whoami
            "1.3.6.1.4.1.4203.1.11.1",  # password modify
        ]
        data['supportedControl'] = [
            "2.16.840.1.113730.3.4.4",  # password expire policy
        ]
        data['domainFunctionality'].append('0')
        data['supportedLDAPPolicies'] = [
            'MaxConnIdleTime',
            'MaxPageSize',
            'MaxValRange',
        ]
        data['supportedCapabilities'] = [
            "1.2.840.113556.1.4.1791",  # LDAP_INTEG_OID
        ]

        return data

    def cast_filter(self, filter_: ASN1Row) -> UnaryExpression:
        """Convert asn1 row filter_ to sqlalchemy obj.

        :param ASN1Row filter_: requested filter_
        :param AsyncSession session: sa session
        :return UnaryExpression: condition
        """
        return cast_filter2sql(filter_)

    async def handle(
        self, session: AsyncSession,
        ldap_session: LDAPSession,
        settings: Settings,
    ) -> AsyncGenerator[
        SearchResultDone | SearchResultReference | SearchResultEntry, None,
    ]:
        """Search tree.

        Provides following responses:
        Entry -> Reference (optional) -> Done
        """
        async with ldap_session.lock() as user:
            async for response in self.get_result(
                    bool(user), session, settings):
                yield response

    async def get_result(
        self, user_logged: bool,
        session: AsyncSession,
        settings: Settings,
    ) -> AsyncGenerator[SearchResultDone, None]:
        """Create response.

        :param bool user_logged: is user in session
        :param AsyncSession session: sa session
        :yield SearchResult: search result
        """
        is_root_dse = self.scope == Scope.BASE_OBJECT and not self.base_object
        is_schema = self.base_object.lower() == 'cn=schema'

        if not (is_root_dse or is_schema) and not user_logged:
            yield SearchResultDone(**INVALID_ACCESS_RESPONSE)
            return

        if self.scope == Scope.BASE_OBJECT and (is_root_dse or is_schema):
            if is_schema:
                yield self._get_subschema()
            elif is_root_dse:
                attrs = await self.get_root_dse(session, settings)
                yield SearchResultEntry(
                    object_name='',
                    partial_attributes=[
                        PartialAttribute(type=name, vals=values)
                        for name, values in attrs.items()],
                )
            yield SearchResultDone(result_code=LDAPCodes.SUCCESS)
            return

        query = self.build_query(await get_base_directories(session))

        try:
            cond = self.cast_filter(self.filter)
            query = query.filter(cond)
        except Exception as err:
            logger.error(f'Filter syntax error {err}')
            yield SearchResultDone(result_code=LDAPCodes.PROTOCOL_ERROR)
            return

        query, pages_total, count = await self.paginate_query(query, session)

        async for response in self.tree_view(query, session, settings):
            yield response

        yield SearchResultDone(
            result_code=LDAPCodes.SUCCESS,
            total_pages=pages_total,
            total_objects=count,
        )

    @cached_property
    def member_of(self) -> bool:  # noqa
        return 'memberof' in self.requested_attrs or self.all_attrs

    @cached_property
    def all_attrs(self) -> bool:  # noqa
        return '*' in self.requested_attrs or not self.requested_attrs

    def build_query(self, base_directories: list[Directory]) -> Select:
        """Build tree query."""
        query = select(  # noqa: ECE001
            Directory)\
            .join(User, isouter=True)\
            .join(Directory.attributes, isouter=True)\
            .join(Directory.path)\
            .options(
                selectinload(Directory.path),
                subqueryload(Directory.attributes),
                joinedload(Directory.user),
                joinedload(Directory.group))\
            .distinct(Directory.id)

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
                query = query.filter(or_(*[
                    get_path_filter(domain.path.path)
                    for domain in base_directories]))

        elif self.scope == Scope.SINGLE_LEVEL:
            query = query.filter(
                func.cardinality(Path.path) == len(search_path) + 1,
                get_path_filter(
                    column=Path.path[0:len(search_path)],
                    path=search_path))

        elif self.scope == Scope.WHOLE_SUBTREE and not root_is_base:
            query = query.filter(get_path_filter(
                column=Path.path[1:len(search_path)],
                path=search_path))

        if self.member_of:
            s1 = selectinload(Directory.group).selectinload(
                Group.parent_groups).selectinload(
                    Group.directory).selectinload(Directory.path)

            s2 = selectinload(Directory.user).selectinload(
                User.groups).selectinload(
                    Group.directory).selectinload(Directory.path)

            s3 = selectinload(Directory.group).selectinload(
                Group.users).selectinload(
                    User.directory).selectinload(Directory.path)

            query = query.options(s1, s2, s3)

        return query  # noqa

    async def paginate_query(
        self, query: Select, session: AsyncSession,
    ) -> tuple[Select, int, int]:
        """Paginate query.

        :param _type_ query: _description_
        :param _type_ session: _description_
        :return tuple[select, int, int]: query, pages_total, count
        """
        if self.page_number is None:
            return query, 0, 0

        count = await session.scalar(
            select(func.count()).select_from(query))
        start = (self.page_number - 1) * self.size_limit
        end = start + self.size_limit
        query = query.offset(start).limit(end)

        return query, int(ceil(count / float(self.size_limit))), count

    async def tree_view(
            self, query: Select,
            session: AsyncSession,
            settings: Settings) -> AsyncGenerator[SearchResultEntry, None]:
        """Yield all resulted directories."""
        directories = await session.stream_scalars(query)
        # logger.debug(query.compile(compile_kwargs={"literal_binds": True}))  # noqa

        async for directory in directories:
            attrs = defaultdict(list)
            groups = []

            for attr in directory.attributes:
                if isinstance(attr.value, str):
                    value = attr.value.replace('\\x00', '\x00')
                else:
                    value = attr.bvalue

                attrs[attr.name].append(value)

            distinguished_name = directory.path_dn

            attrs['distinguishedName'].append(distinguished_name)
            attrs['whenCreated'].append(
                directory.created_at.strftime("%Y%m%d%H%M%S.0Z"),
            )

            if directory.user:
                if directory.user.account_exp is None:
                    attrs['accountExpires'].append('0')
                else:
                    attrs['accountExpires'].append(
                        dt_to_ft(directory.user.account_exp),
                    )
                if directory.user.last_logon is None:
                    attrs['lastLogon'].append('0')
                else:
                    attrs['lastLogon'].append(
                        get_windows_timestamp(directory.user.last_logon),
                    )
                    attrs['authTimestamp'].append(directory.user.last_logon)

            if self.member_of:
                if 'group' in attrs['objectClass'] and (
                        directory.group):
                    groups += directory.group.parent_groups

                    for user in directory.group.users:
                        attrs['member'].append(user.directory.path_dn)

                if 'user' in attrs['objectClass'] and (
                        directory.user):
                    groups += directory.user.groups

            for group in groups:
                attrs['memberOf'].append(group.directory.path_dn)

            if directory.user:
                if self.all_attrs:
                    user_fields = directory.user.search_fields.keys()
                else:
                    user_fields = (
                        attr for attr in self.requested_attrs if (
                            directory.user and (
                                attr in directory.user.search_fields)))
            else:
                user_fields = []

            if directory.group:
                if self.all_attrs:
                    group_fields = directory.group.search_fields.keys()
                else:
                    group_fields = (
                        attr for attr in self.requested_attrs if (
                            directory.group and (
                                attr in directory.group.search_fields)))
            else:
                group_fields = []

            for attr in group_fields:
                attribute = getattr(directory.group, attr)
                attrs[directory.group.search_fields[attr]].append(attribute)

            for attr in user_fields:
                if attr == 'accountexpires':
                    continue
                attribute = getattr(directory.user, attr)
                attrs[directory.user.search_fields[attr]].append(attribute)

            if self.all_attrs:
                directory_fields = directory.search_fields.keys()
            else:
                directory_fields = (
                    attr for attr in self.requested_attrs
                    if attr in directory.search_fields)

            for attr in directory_fields:
                attribute = getattr(directory, attr)
                if attr == 'objectsid':
                    attribute = string_to_sid(attribute)
                elif attr == 'objectguid':
                    attribute = attribute.bytes_le
                attrs[directory.search_fields[attr]].append(attribute)

            yield SearchResultEntry(
                object_name=distinguished_name,
                partial_attributes=[
                    PartialAttribute(type=key, vals=value)
                    for key, value in attrs.items()],
            )

"""Search protocol."""

import sys
from collections import defaultdict
from functools import cached_property
from math import ceil
from typing import AsyncGenerator, ClassVar

from loguru import logger
from pydantic import Field
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import joinedload, selectinload, subqueryload
from sqlalchemy.sql.expression import Select

from config import VENDOR_NAME, VENDOR_VERSION
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, Session
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
    get_attribute_types,
    get_base_dn,
    get_generalized_now,
    get_object_classes,
)
from models.ldap3 import CatalogueSetting, Directory, Group, Path, User

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

    base_object: str = ''
    scope: Scope
    deref_aliases: DerefAliases
    size_limit: int = Field(ge=0, le=sys.maxsize, example=1000)
    time_limit: int = Field(ge=0, le=sys.maxsize, example=1000)
    types_only: bool
    filter: ASN1Row = Field(...)  # noqa: A003
    attributes: list[str]

    page_number: int | None = Field(None, ge=1)  # only API method

    class Config:
        """Allow class to use property."""

        arbitrary_types_allowed = True
        keep_untouched = (cached_property,)

    @classmethod
    def from_data(cls, data):  # noqa: D102
        (
            base_object,
            scope,
            deref_aliases,
            size_limit,
            time_limit,
            types_only,
            filter_,
            attributes,
        ) = data[:8]

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
    def requested_attrs(self):  # noqa
        return [attr.lower() for attr in self.attributes]

    async def get_root_dse(
            self, session: AsyncSession) -> defaultdict[str, list[str]]:
        """Get RootDSE.

        :param list[str] attributes: list of requested attrs
        :return defaultdict[str, list[str]]: queried attrs
        """
        attributes = self.requested_attrs
        data = defaultdict(list)
        clause = [CatalogueSetting.name.ilike(name) for name in attributes]
        res = await session.execute(
            select(CatalogueSetting).where(*clause))

        for setting in res.scalars():
            data[setting.name].append(setting.value)

        data.pop('defaultNamingContext', None)

        base_dn = await get_base_dn(session)
        domain = await get_base_dn(session, True)
        schema = 'CN=Schema'

        if attributes == ['subschemasubentry']:
            data['subschemaSubentry'].append(schema)
            return data

        data['dnsHostName'].append(domain)
        data['objectClass'].append('top')
        data['serverName'].append(domain)
        data['serviceName'].append(domain)
        data['dsServiceName'].append(domain)
        data['LDAPServiceName'].append(domain)
        data['vendorName'].append(VENDOR_NAME)
        data['vendorVersion'].append(VENDOR_VERSION)
        data['namingContexts'].append(base_dn)
        data['namingContexts'].append(schema)
        data['rootDomainNamingContext'].append(base_dn)
        data['supportedLDAPVersion'].append(3)
        data['defaultNamingContext'].append(base_dn)
        data['currentTime'].append(get_generalized_now())
        data['subschemaSubentry'].append(schema)
        data['schemaNamingContext'].append(schema)
        # data['configurationNamingContext'].append(schema)  # noqa
        data['supportedSASLMechanisms'] = ['ANONYMOUS', 'EXTERNAL', 'PLAIN']
        data['highestCommittedUSN'].append('126991')
        data['supportedControl'] = [
            # '1.2.840.113556.1.4.319',
            # '1.2.840.113556.1.4.529',
            # '1.2.840.113556.1.4.1948',
        ]
        data['domainFunctionality'].append('0')
        data['supportedLDAPPolicies'] = [
            'MaxPoolThreads',
            'MaxDatagramRecv',
            'MaxReceiveBuffer',
            'InitRecvTimeout',
            'MaxConnections',
            'MaxConnIdleTime',
            'MaxPageSize',
            'MaxQueryDuration',
            'MaxTempTableSize',
            'MaxResultSetSize',
            'MaxNotificationPerConn',
            'MaxValRange',
        ]
        data['supportedCapabilities'] = [
            '1.2.840.113556.1.4.2237',
            '1.2.840.113556.1.4.1670',
            '1.2.840.113556.1.4.1791',
        ]
        return data

    def _get_subschema(self, dn):
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

    @staticmethod
    def _get_full_dn(path: Path, dn) -> str:
        return ','.join(reversed(path.path)) + ',' + dn

    def cast_filter(self, filter_, query):
        """Convert asn1 row filter_ to sqlalchemy obj.

        :param ASN1Row filter_: requested filter_
        :param sqlalchemy query: sqlalchemy query obj
        :return tuple: condition and query objects
        """
        return cast_filter2sql(filter_, query)

    async def handle(
        self, ldap_session: Session, session: AsyncSession,
    ) -> AsyncGenerator[
        SearchResultDone | SearchResultReference | SearchResultEntry, None,
    ]:
        """Search tree.

        Provides following responses:
        Entry -> Reference (optional) -> Done
        """
        async with ldap_session.lock() as user:
            async for response in self.get_result(bool(user), session):
                yield response

    async def get_result(self, user_logged: bool, session: AsyncSession):
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

        if self.scope == Scope.BASE_OBJECT:
            if (metadata := await self.get_base_data(session)):
                yield metadata
                yield SearchResultDone(result_code=LDAPCodes.SUCCESS)
                return

        query = self.build_query(await get_base_dn(session))

        try:
            cond, query = self.cast_filter(self.filter, query)
            query = query.filter(cond)
        except Exception as err:
            logger.error(f'Filter syntax error {err}')
            yield SearchResultDone(result_code=LDAPCodes.PROTOCOL_ERROR)
            return

        query, pages_total, count = await self.paginate_query(query, session)

        async for response in self.tree_view(query, session):
            yield response

        yield SearchResultDone(
            result_code=LDAPCodes.SUCCESS,
            total_pages=pages_total,
            total_objects=count,
        )

    async def get_base_data(
            self, session: AsyncSession) -> SearchResultEntry | None:
        """Get base server data.

        :param AsyncSession session: sqlalchemy session
        :return SearchResultEntry | None: optional result
        """
        dn = await get_base_dn(session)

        if self.base_object:
            if self.base_object.lower() == dn.lower():  # noqa  # domain info
                attrs = defaultdict(list)
                attrs['serverState'].append('1')
                attrs['objectClass'].append('domain')
                attrs['objectClass'].append('domainDNS')
                attrs['objectClass'].append('top')

                return SearchResultEntry(
                    object_name=dn,
                    partial_attributes=[
                        PartialAttribute(type=key, vals=value)
                        for key, value in attrs.items()])

            elif self.base_object.lower() == 'cn=schema':  # subschema subentry
                return self._get_subschema(dn)

        else:
            attrs = await self.get_root_dse(session)  # RootDSE
            return SearchResultEntry(
                object_name='',
                partial_attributes=[
                    PartialAttribute(type=name, vals=values)
                    for name, values in attrs.items()],
            )

        return None

    @cached_property
    def member_of(self):  # noqa
        return 'memberof' in self.requested_attrs or self.all_attrs

    @cached_property
    def all_attrs(self):  # noqa
        return '*' in self.requested_attrs or not self.requested_attrs

    def build_query(self, dn) -> Select:
        """Build tree query."""
        query = select(  # noqa: ECE001
            Directory)\
            .join(User, isouter=True)\
            .join(Directory.attributes, isouter=True)\
            .join(Directory.path)\
            .options(
                selectinload(Directory.path),
                subqueryload(Directory.attributes),
                joinedload(Directory.user))\
            .distinct(Directory.id)

        root_is_base = self.base_object.lower() == dn.lower()
        base_obj = self.base_object.lower().removesuffix(
            ',' + dn.lower()).split(',')
        search_path = [path for path in reversed(base_obj) if path]

        if self.scope == Scope.BASE_OBJECT and self.base_object:
            query = query.filter(Path.path == search_path)

        elif self.scope == Scope.SINGLEL_EVEL:
            if root_is_base:
                query = query.filter(func.cardinality(Path.path) == 1)
            else:
                query = query.filter(
                    func.cardinality(Path.path) == len(search_path) + 1,
                    Path.path[0:len(search_path)] == search_path,
                )

        elif self.scope == Scope.WHOLE_SUBTREE and not root_is_base:
            query = query.filter(Path.path[1:len(search_path)] == search_path)

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

    async def tree_view(self, query, session: AsyncSession):
        """Yield all resulted directories."""
        directories = await session.stream_scalars(query)
        dn = await get_base_dn(session)
        # logger.debug(query.compile(compile_kwargs={"literal_binds": True}))  # noqa

        async for directory in directories:
            attrs = defaultdict(list)
            groups = []

            for attr in directory.attributes:
                attrs[attr.name].append(attr.value)

            if self.member_of:
                if 'group' in attrs['objectClass'] and (
                        directory.group):
                    groups += directory.group.parent_groups

                    attrs['distinguishedName'].append(
                        self._get_full_dn(directory.path, dn))

                    for user in directory.group.users:
                        attrs['member'].append(
                            self._get_full_dn(user.directory.path, dn))

                if 'user' in attrs['objectClass'] and (
                        directory.user):
                    groups += directory.user.groups

            for group in groups:
                attrs['memberOf'].append(
                    self._get_full_dn(group.directory.path, dn))

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

            for attr in user_fields:
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
                attrs[directory.search_fields[attr]].append(attribute)

            yield SearchResultEntry(
                object_name=self._get_full_dn(directory.path, dn),
                partial_attributes=[
                    PartialAttribute(type=key, vals=value)
                    for key, value in attrs.items()],
            )

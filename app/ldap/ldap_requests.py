"""LDAP requests structure bind."""

import re
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import AsyncGenerator, ClassVar

from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.future import select
from sqlalchemy.orm import joinedload, selectinload

from config import settings
from models.database import async_session
from models.ldap3 import CatalogueSetting, Directory, Group, Path, User

from .asn1parser import ASN1Row
from .dialogue import LDAPCodes, Session
from .filter_interpreter import cast_filter2sql
from .ldap_responses import (
    BAD_SEARCH_RESPONSE,
    BaseResponse,
    BindResponse,
    PartialAttribute,
    SearchResultDone,
    SearchResultEntry,
    SearchResultReference,
)
from .objects import DerefAliases, Scope
from .utils import (
    get_attribute_types,
    get_base_dn,
    get_generalized_now,
    get_object_classes,
)

email_re = re.compile(
    r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")


ATTRIBUTE_TYPES = get_attribute_types()
OBJECT_CLASSES = get_object_classes()


class BaseRequest(ABC, BaseModel):
    """Base request builder."""

    @property
    @abstractmethod
    def PROTOCOL_OP(self) -> int:  # noqa: N802, D102
        """Protocol OP response code."""

    @classmethod
    @abstractmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'BaseRequest':
        """Create structure from ASN1Row dataclass list."""
        raise NotImplementedError(f'Tried to access {cls.PROTOCOL_OP}')

    @abstractmethod
    async def handle(self, ldap_session: Session) -> \
            AsyncGenerator[BaseResponse, None]:
        """Handle message with current user."""
        yield BaseResponse()  # type: ignore


class AuthChoice(ABC, BaseModel):
    """Auth base class."""

    @abstractmethod
    def is_valid(self, user: User):
        """Validate state."""

    @abstractmethod
    def is_anonymous(self):
        """Return true if anonymous."""


class SimpleAuthentication(AuthChoice):
    """Simple auth form."""

    password: str

    def is_valid(self, user: User):
        return self.password == user.password

    def is_anonymous(self):
        return not self.password


class SaslAuthentication(AuthChoice):
    """Sasl auth form."""

    mechanism: str
    credentials: bytes


class BindRequest(BaseRequest):
    """Bind request fields mapping."""

    PROTOCOL_OP: ClassVar[int] = 0x0

    version: int
    name: str
    authentication_choice: SimpleAuthentication | SaslAuthentication =\
        Field(..., alias='AuthenticationChoice')

    @classmethod
    def from_data(cls, data) -> 'BindRequest':
        """Get bind from data dict."""
        auth = data[2].tag_id.value

        if auth == 0:
            auth_choice = SimpleAuthentication(password=data[2].value)
        elif auth == 3:  # noqa: R506
            raise NotImplementedError('Sasl not supported')  # TODO: Add SASL
        else:
            raise ValueError('Auth version not supported')

        return cls(
            version=data[0].value,
            name=data[1].value,
            AuthenticationChoice=auth_choice,
        )

    def get_domain(self):
        """Get domain from name."""
        return '.'.join([
            item[3:].lower() for item in self.name.split(',')
            if item[:2] in ('DC', 'dc')
        ])

    def get_path(self):
        """Get path from name."""
        return [
            item.lower() for item in reversed(self.name.split(','))
            if not item[:2] in ('DC', 'dc')
        ]

    async def handle(self, ldap_session: Session) -> \
            AsyncGenerator[BindResponse, None]:
        """Handle bind request, check user and password."""
        if not self.name and self.authentication_choice.is_anonymous():
            yield BindResponse(resultCode=LDAPCodes.SUCCESS)
            return

        bad_response = BindResponse(
            resultCode=LDAPCodes.INVALID_CREDENTIALS,
            matchedDN='',
            errorMessage=(
                '80090308: LdapErr: DSID-0C090447, '
                'comment: AcceptSecurityContext error, '
                'data 52e, v3839'),
        )

        async with async_session() as session:
            if '=' not in self.name:
                if email_re.fullmatch(self.name):
                    cond = User.user_principal_name == self.name
                else:
                    cond = User.sam_accout_name == self.name

                user = await session.scalar(select(User).where(cond))
            else:

                path = await session.scalar(
                    select(Path).where(Path.path == self.get_path()))

                domain = await session.scalar(
                    select(CatalogueSetting)
                    .where(CatalogueSetting.name == 'defaultNamingContext'))

                if not domain or not path:
                    yield bad_response
                    return

                user = await session.scalar(
                    select(User).where(User.directory == path.endpoint))

            if not user:
                yield bad_response
                return

            if not self.authentication_choice.is_valid(user):
                yield bad_response
                return

        await ldap_session.set_user(user)
        yield BindResponse(resultCode=LDAPCodes.SUCCESS, matchedDn='')


class UnbindRequest(BaseRequest):
    """Remove user from ldap_session."""

    PROTOCOL_OP: ClassVar[int] = 2

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'UnbindRequest':
        """Unbind request has no body."""
        return cls()

    async def handle(self, ldap_session: Session) -> \
            AsyncGenerator[BaseResponse, None]:
        """Handle unbind request, no need to send response."""
        await ldap_session.delete_user()
        return  # declare empty async generator and exit
        yield


class SearchRequest(BaseRequest):
    """Search request schema.

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
        derefAlways             (3) },
    sizeLimit       INTEGER (0 ..  maxInt),
    timeLimit       INTEGER (0 ..  maxInt),
    typesOnly       BOOLEAN,
    filter          Filter,
    attributes      AttributeSelection
    }
    """

    PROTOCOL_OP: ClassVar[int] = 3

    base_object: str = ''
    scope: Scope
    deref_aliases: DerefAliases
    size_limit: int = Field(ge=0, le=sys.maxsize)
    time_limit: int = Field(ge=0, le=sys.maxsize)
    types_only: bool
    filter: ASN1Row = Field(...)  # noqa: A003
    attributes: list[str]

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

    def _get_attributes(self):
        return [attr.lower() for attr in self.attributes]

    async def get_root_dse(self) -> defaultdict[str, list[str]]:
        """Get RootDSE.

        :param list[str] attributes: list of requested attrs
        :return defaultdict[str, list[str]]: queried attrs
        """
        attributes = self._get_attributes()
        async with async_session() as session:
            data = defaultdict(list)
            clause = [CatalogueSetting.name.ilike(name) for name in attributes]
            res = await session.execute(
                select(CatalogueSetting).where(*clause))

            for setting in res.scalars():
                data[setting.name].append(setting.value)

            data.pop('defaultNamingContext', None)

        base_dn = await get_base_dn()
        domain = await get_base_dn(True)
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
        data['vendorName'].append(settings.VENDOR_NAME)
        data['namingContexts'].append(base_dn)
        data['namingContexts'].append(schema)
        data['rootDomainNamingContext'].append(base_dn)
        data['supportedLDAPVersion'].append(3)
        data['defaultNamingContext'].append(base_dn)
        data['vendorVersion'].append(settings.VENDOR_VERSION)
        data['currentTime'].append(get_generalized_now())
        data['subschemaSubentry'].append(schema)
        data['schemaNamingContext'].append(schema)
        # data['configurationNamingContext'].append(schema)
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

    async def handle(
        self, ldap_session: Session,
    ) -> AsyncGenerator[
        SearchResultDone | SearchResultReference | SearchResultEntry, None,
    ]:
        """Search tree.

        Provides following responses:
        Entry -> Reference (optional) -> Done
        """
        is_root_dse = self.scope == Scope.BASE_OBJECT and not self.base_object
        is_schema = self.base_object.lower() == 'cn=schema'

        user = await ldap_session.get_user()
        if not (is_root_dse or is_schema) and user is None:
            yield BAD_SEARCH_RESPONSE
            return
        del user

        query = select(  # noqa: ECE001
            Directory)\
            .join(User, isouter=True)\
            .join(Directory.attributes, isouter=True)\
            .join(Directory.path)\
            .options(
                selectinload(Directory.path),
                selectinload(Directory.attributes),
                joinedload(Directory.user))\
            .distinct(Directory.id)

        try:
            cond, query = cast_filter2sql(self.filter, query)
            query = query.filter(cond)
        except Exception as err:
            logger.error(f'Filter syntax error {err}')
            yield SearchResultDone(resultCode=LDAPCodes.OPERATIONS_ERROR)
            return

        async for response in self.tree_view(query):
            yield response
        yield SearchResultDone(resultCode=LDAPCodes.SUCCESS)

    async def tree_view(self, query):
        """Yield tree result."""
        dn = await get_base_dn()

        requested_attrs = self._get_attributes()
        all_attrs = '*' in requested_attrs or not requested_attrs

        member_of = 'memberof' in requested_attrs or all_attrs

        dn_is_base = self.base_object.lower() == dn.lower()
        base_obj = self.base_object.lower().removesuffix(
            ',' + dn.lower()).split(',')
        search_path = [path for path in reversed(base_obj) if path]

        if self.scope == Scope.BASE_OBJECT:
            if self.base_object:
                if dn_is_base:
                    attrs = defaultdict(list)
                    attrs['serverState'].append('1')
                    attrs['objectClass'].append('domain')
                    attrs['objectClass'].append('domainDNS')
                    attrs['objectClass'].append('top')

                    yield SearchResultEntry(
                        object_name=dn,
                        partial_attributes=[
                            PartialAttribute(type=key, vals=value)
                            for key, value in attrs.items()])
                    return

                elif self.base_object.lower() == 'cn=schema':
                    yield self._get_subschema(dn)
                    return

                query = query.filter(Path.path == search_path)
            else:
                attrs = await self.get_root_dse()
                yield SearchResultEntry(
                    object_name='',
                    partial_attributes=[
                        PartialAttribute(type=name, vals=values)
                        for name, values in attrs.items()],
                )
                return

        elif self.scope == Scope.SINGLEL_EVEL:
            if dn_is_base:
                query = query.filter(func.cardinality(Path.path) == 1)
            else:
                query = query.filter(
                    func.cardinality(Path.path) == len(search_path) + 1,
                    Path.path[0:len(search_path)] == search_path,
                )

        elif self.scope == Scope.WHOLE_SUBTREE and not dn_is_base:
            query = query.filter(Path.path[0:len(search_path)] == search_path)

        if member_of:
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

        async with async_session() as session:
            directories = await session.stream_scalars(query)
            # logger.debug(query.compile(compile_kwargs={"literal_binds": True}))

            async for directory in directories:
                attrs = defaultdict(list)
                groups = []

                if member_of:
                    if directory.object_class.lower() == 'group' and (
                            directory.group):
                        groups += directory.group.parent_groups

                        attrs['distinguishedName'].append(
                            self._get_full_dn(directory.path, dn))

                        for user in directory.group.users:
                            attrs['member'].append(
                                self._get_full_dn(user.directory.path, dn))

                    if directory.object_class.lower() == 'user' and (
                            directory.user):
                        groups += directory.user.groups

                for group in groups:
                    attrs['memberOf'].append(
                        self._get_full_dn(group.directory.path, dn))

                if directory.user:
                    if all_attrs:
                        user_fields = directory.user.search_fields.keys()
                    else:
                        user_fields = (
                            attr for attr in requested_attrs if (
                                directory.user and (
                                    attr in directory.user.search_fields)))
                else:
                    user_fields = []

                for attr in user_fields:
                    attribute = getattr(directory.user, attr)
                    attrs[directory.user.search_fields[attr]].append(attribute)

                if all_attrs:
                    directory_fields = directory.search_fields.keys()
                else:
                    directory_fields = (
                        attr for attr in requested_attrs
                        if attr in directory.search_fields)

                for attr in directory_fields:
                    attribute = getattr(directory, attr)
                    attrs[directory.search_fields[attr]].append(attribute)

                for attr in directory.attributes:
                    attrs[attr.name].append(attr.value)

                yield SearchResultEntry(
                    object_name=self._get_full_dn(directory.path, dn),
                    partial_attributes=[
                        PartialAttribute(type=key, vals=value)
                        for key, value in attrs.items()],
                )


class ModifyRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 6


class AddRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 8


class DeleteRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 10


class ModifyDNRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 12


class CompareRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 14


class AbandonRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 16
    message_id: int

    @classmethod
    def from_data(cls, data):
        """Create structure from ASN1Row dataclass list."""
        logger.debug(data)
        return cls(message_id=1)

    async def handle(self, ldap_session: Session):
        """Handle message with current user."""
        import asyncio
        await asyncio.sleep(0)
        return
        yield


class ExtendedRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 23


protocol_id_map: dict[int, type[BaseRequest]] = \
    {request.PROTOCOL_OP: request  # type: ignore
        for request in BaseRequest.__subclasses__()}


#     7: 'Modify Response',
#     9: 'Add Response',
#     11: 'Delete Response',
#     13: 'Modify DN Response',
#     15: 'compare Response',
#     19: 'Search Result Reference',
#     24: 'Extended Response',
#     25: 'intermediate Response',

"""LDAP requests structure bind."""

import re
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import AsyncGenerator, ClassVar

from pydantic import BaseModel, Field, validator
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
from .utils import get_base_dn, get_generalized_now

email_re = re.compile(
    r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")


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
        raise NotImplementedError()

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

        ldap_session.user = user
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
        if not ldap_session.user:
            raise ValueError('User not authed')
        ldap_session.name = None
        ldap_session.user = None
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

    base_object: str | None
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

    def _get_base_obj(self):
        assert self.base_object, 'no baseObject'  # noqa: S101
        return [obj.lower() for obj in self.base_object.split(',')]

    @validator('base_object')
    def empty_str_to_none(cls, v):  # noqa: N805
        """Set base_object value to None if it's value is empty str."""
        if v == '':
            return None
        return v

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

        base_dn = await get_base_dn()
        domain = await get_base_dn(True)

        data['dnsHostName'].append(domain)
        data['serviceName'].append(domain)
        data['vendorName'].append(settings.VENDOR_NAME)
        data['namingContexts'].append(base_dn)
        data['rootDomainNamingContext'].append(base_dn)
        data['supportedldapversion'].append(3)
        data['defaultNamingContext'].append(base_dn)
        data['vendorVersion'].append(settings.VENDOR_VERSION)
        data['currentTime'].append(get_generalized_now())
        return data

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
        views = {
            Scope.BASE_OBJECT: self.base_object_view,
            Scope.SINGLEL_EVEL: self.single_level_view,
            Scope.WHOLE_SUBTREE: self.whole_subtree_view,
        }
        handler = views[self.scope]
        is_root_dse = handler == self.base_object_view and not self.base_object

        if not is_root_dse and ldap_session.user is None:
            yield BAD_SEARCH_RESPONSE
            return

        try:
            condition = cast_filter2sql(self.filter)
        except Exception:
            yield SearchResultDone(resultCode=LDAPCodes.OPERATIONS_ERROR)
            return

        async for response in handler(condition):
            yield response
        yield SearchResultDone(resultCode=LDAPCodes.SUCCESS)

    async def base_object_view(self, condition):
        """Yield base object response."""
        if self.base_object is None:
            attrs = await self.get_root_dse()
            yield SearchResultEntry(
                object_name='',
                partial_attributes=[
                    PartialAttribute(type=name, vals=values)
                    for name, values in attrs.items()],
            )
        else:
            query = select(Directory)\
                .join(Path).filter(Path.path == self._get_base_obj())

            if condition is not None:
                query = query.filter(condition)

            async with async_session() as session:
                dirs = await session.execute(query)

            for directory in dirs.scalars():
                yield SearchResultEntry(
                    object_name=''.join(directory.path.path),
                    partial_attributes=[
                        PartialAttribute(type='objectClass', vals=oc)
                        for oc in directory.get_object_class()],
                )

    async def single_level_view(self, condition):
        """Yield single level result."""
        dn = await get_base_dn()
        self.base_object.removesuffix(dn)

        subquery = select(Path).options(  # noqa: ECE001
            joinedload(Path.endpoint, Path.directories)).where(
            Path.path == self.base_object.lower().split(','),
        ).subquery()

        query = select(Directory)\
            .filter(Directory.parent_id == subquery.c.endpoint_id)\
            .options(joinedload(Directory.path))

        if condition is not None:
            query = query.filter(condition)

        async with async_session() as session:
            dirs = await session.scalars(query)

            for directory in dirs:
                yield SearchResultEntry(
                    object_name=self._get_full_dn(directory.path, dn),
                    partial_attributes=[
                        PartialAttribute(type='objectClass', vals=oc)
                        for oc in directory.get_object_class()],
                )

    async def whole_subtree_view(self, condition):
        """Yield subtree result."""
        query = select(Directory)\
            .join(User, isouter=True)\
            .join(Directory.attributes, isouter=True)\
            .options(
                selectinload(Directory.path),
                selectinload(Directory.attributes))

        member_of = 'memberof' in self._get_attributes()

        if member_of:
            s1 = selectinload(Directory.group).selectinload(
                Group.parent_groups).selectinload(
                    Group.directory).selectinload(Directory.path)

            s2 = selectinload(Directory.user).selectinload(
                User.groups).selectinload(
                    Group.directory).selectinload(Directory.path)

            query = query.options(s1, s2)

        if condition is not None:
            query = query.filter(condition)

        async with async_session() as session:
            directories = await session.stream_scalars(query)

            dn = await get_base_dn()
            async for directory in directories:
                attrs = defaultdict(list)

                if directory.object_class.lower() == 'group' and member_of:
                    for group in directory.group.parent_groups:
                        attrs['memberOf'].append(
                            self._get_full_dn(group.directory.path, dn))
                if directory.object_class.lower() == 'user':
                    if member_of:
                        for group in directory.user.groups:
                            attrs['memberOf'].append(
                                self._get_full_dn(group.directory.path, dn))

                    user_fields = (
                        attr for attr in self._get_attributes()
                        if attr in directory.user.search_fields)

                    for attr in user_fields:
                        attribute = getattr(directory.user, attr)
                        attrs[directory.user.search_fields[attr]].append(
                            attribute)

                directory_fields = (
                    attr for attr in self._get_attributes()
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

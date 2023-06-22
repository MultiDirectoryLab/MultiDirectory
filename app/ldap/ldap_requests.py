"""LDAP requests structure bind."""
import asyncio
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import AsyncGenerator, ClassVar

from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, func, or_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import joinedload, selectinload, subqueryload

from config import settings
from models.ldap3 import (
    Attribute,
    CatalogueSetting,
    Directory,
    Group,
    Path,
    User,
)
from security import verify_password

from .asn1parser import ASN1Row
from .dialogue import LDAPCodes, Operation, Session
from .filter_interpreter import cast_filter2sql
from .ldap_responses import (
    BAD_SEARCH_RESPONSE,
    AddResponse,
    BaseResponse,
    BindResponse,
    DeleteResponse,
    ModifyDNResponse,
    ModifyResponse,
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
    get_user,
    validate_entry,
)

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
    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[BaseResponse, None]:
        """Handle message with current user."""
        yield BaseResponse()  # type: ignore

    class Config:  # noqa: D106
        fields = {'PROTOCOL_OP': {'exclude': True}}

    async def handle_api(
        self, user,
        session: AsyncSession,
        single: bool = True,
    ) -> list[BaseResponse] | BaseResponse:
        """Hanlde response with api user.

        :param DBUser user: user from db
        :param AsyncSession session: db session
        :return list[BaseResponse]: list of handled responses
        """
        responses = [
            response async for response in self.handle(Session(user), session)]

        if single:
            return responses[0]
        return responses


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

    def is_valid(self, user: User | None) -> bool:
        """Check if pwd is valid for user.

        :param User | None user: indb user
        :return bool: status
        """
        password = getattr(user, "password", None)
        return bool(password) and verify_password(self.password, password)

    def is_anonymous(self) -> bool:
        """Check if auth is anonymous.

        :return bool: status
        """
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

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[BindResponse, None]:
        """Handle bind request, check user and password."""
        if not self.name and self.authentication_choice.is_anonymous():
            yield BindResponse(result_code=LDAPCodes.SUCCESS)
            return

        bad_response = BindResponse(
            result_code=LDAPCodes.INVALID_CREDENTIALS,
            matchedDN='',
            errorMessage=(
                '80090308: LdapErr: DSID-0C090447, '
                'comment: AcceptSecurityContext error, '
                'data 52e, v3839'),
        )

        user = await get_user(session, self.name)

        if not user or not self.authentication_choice.is_valid(user):
            yield bad_response
            return

        await ldap_session.set_user(user)
        yield BindResponse(result_code=LDAPCodes.SUCCESS, matchedDn='')


class UnbindRequest(BaseRequest):
    """Remove user from ldap_session."""

    PROTOCOL_OP: ClassVar[int] = 2

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'UnbindRequest':
        """Unbind request has no body."""
        return cls()

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[BaseResponse, None]:
        """Handle unbind request, no need to send response."""
        await ldap_session.delete_user()
        return  # declare empty async generator and exit
        yield


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
    size_limit: int = Field(ge=0, le=sys.maxsize, example=10000)
    time_limit: int = Field(ge=0, le=sys.maxsize, example=10000)
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

    async def get_root_dse(
            self, session: AsyncSession) -> defaultdict[str, list[str]]:
        """Get RootDSE.

        :param list[str] attributes: list of requested attrs
        :return defaultdict[str, list[str]]: queried attrs
        """
        attributes = self._get_attributes()
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
            yield SearchResultDone(**BAD_SEARCH_RESPONSE)
            return

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

        try:
            cond, query = self.cast_filter(self.filter, query)
            query = query.filter(cond)
        except Exception as err:
            logger.error(f'Filter syntax error {err}')
            yield SearchResultDone(result_code=LDAPCodes.OPERATIONS_ERROR)
            return

        async for response in self.tree_view(query, session):
            yield response
        yield SearchResultDone(result_code=LDAPCodes.SUCCESS)

    async def tree_view(self, query, session: AsyncSession):
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
                if dn_is_base:  # noqa
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
                attrs = await self.get_root_dse(session)
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

        directories = await session.stream_scalars(query)
        # logger.debug(query.compile(compile_kwargs={"literal_binds": True}))  # noqa

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


class Changes(BaseModel):
    """Changes for mod request."""

    operation: Operation
    modification: PartialAttribute


class ModifyRequest(BaseRequest):
    """Modify request.

    ```
    ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        object          LDAPDN,
        changes         SEQUENCE OF change SEQUENCE {
            operation       ENUMERATED {
                add     (0),
                delete  (1),
                replace (2),
            },
            modification    PartialAttribute
        }
    }
    ```
    """

    PROTOCOL_OP: ClassVar[int] = 6

    object: str  # noqa: A003
    changes: list[Changes]

    @classmethod
    def from_data(cls, data):  # noqa: D102
        entry, proto_changes = data

        changes = []
        for change in proto_changes.value:
            changes.append(Changes(
                operation=Operation(int(change.value[0].value)),
                modification=PartialAttribute(
                    type=change.value[1].value[0].value,
                    vals=[
                        attr.value for attr in change.value[1].value[1].value],
                ),
            ))
        return cls(object=entry.value, changes=changes)

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[ModifyResponse, None]:
        """Change request handler."""
        if not ldap_session.user:
            yield ModifyResponse(**BAD_SEARCH_RESPONSE)
            return

        base_dn = await get_base_dn()
        if not validate_entry(self.object.lower()):
            yield ModifyResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        obj = self.object.lower().removesuffix(
            ',' + base_dn.lower()).split(',')
        search_path = reversed(obj)

        query = select(   # noqa: ECE001
            Directory)\
            .join(Directory.path)\
            .join(Directory.attributes)\
            .join(User, isouter=True)\
            .options(
                selectinload(Directory.paths),
                joinedload(Directory.user))\
            .filter(Path.path == search_path)

        directory = await session.scalar(query)

        if len(obj) > 1 and not directory:
            yield ModifyResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        for change in self.changes:
            if change.operation == Operation.ADD:
                await self._add(change, directory, session)

            elif change.operation == Operation.DELETE:
                attrs = []
                name = change.modification.type.lower()

                for value in change.modification.vals:
                    if name not in (
                            Directory.search_fields | User.search_fields):
                        attrs.append(and_(
                            Attribute.name == change.modification.type,
                            Attribute.value == value))

                if attrs:
                    del_query = delete(Attribute).filter(
                        Attribute.directory == directory, or_(*attrs))

                    await session.execute(del_query)
                    await session.commit()

            elif change.operation == Operation.REPLACE:
                await session.delete(directory.attributes)
                await session.commit()
                await self._add(change, directory, session)

        yield ModifyResponse(result_code=LDAPCodes.SUCCESS)

    async def _add(
        self, change: Changes,
        directory: Directory,
        session: AsyncSession,
    ):
        attrs = []
        for value in change.modification.vals:
            name = change.modification.type.lower()

            if name in Directory.search_fields:
                setattr(directory, name, value)

            elif name in User.search_fields and directory.user:
                setattr(directory.user, name, value)

            else:
                attrs.append(Attribute(
                    name=change.modification.type,
                    value=value,
                    directory=directory,
                ))
        session.add_all(attrs)
        await session.commit()


class AddRequest(BaseRequest):
    """Add new entry.

    ```
    AddRequest ::= [APPLICATION 8] SEQUENCE {
        entry           LDAPDN,
        attributes      AttributeList
    }

    AttributeList ::= SEQUENCE OF attribute Attribute
    ```
    """

    PROTOCOL_OP: ClassVar[int] = 8

    entry: str
    attributes: list[PartialAttribute]

    @classmethod
    def from_data(cls, data):  # noqa: D102
        entry, attributes = data
        attributes = [
            PartialAttribute(
                type=attr.value[0].value,
                vals=[val.value for val in attr.value[1].value])
            for attr in attributes.value
        ]
        return cls(entry=entry.value, attributes=attributes)

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[AddResponse, None]:
        """Add request handler."""
        if not ldap_session.user:
            yield AddResponse(**BAD_SEARCH_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield AddResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        base_dn = await get_base_dn()
        obj = self.entry.lower().removesuffix(
            ',' + base_dn.lower()).split(',')

        if len(obj) == 1:
            new_dir = Directory(
                object_class='',
                name=obj[0].split('=')[1],
            )
            path = new_dir.create_path()
            ext_path = [path]

        else:
            new_dn = obj.pop(0)
            search_path = reversed(obj)
            query = select(Directory)\
                .join(Directory.path)\
                .options(selectinload(Directory.paths))\
                .filter(Path.path == search_path)
            parent = await session.scalar(query)

            if not parent:
                yield AddResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
                return

            new_dir = Directory(
                object_class='',
                name=new_dn.split('=')[1],
                parent=parent,
            )
            path = new_dir.create_path(parent)
            ext_path = parent.paths + [path]

        attributes = []

        for attr in self.attributes:
            for value in attr.vals:
                attributes.append(
                    Attribute(name=attr.type, value=value, directory=new_dir))

        async with session.begin_nested():
            try:
                session.add_all([new_dir, path] + attributes)
                path.directories.extend([p.endpoint for p in ext_path])
                await session.commit()
            except IntegrityError:
                await session.rollback()
                yield AddResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
                return

        yield AddResponse(result_code=LDAPCodes.SUCCESS)


class DeleteRequest(BaseRequest):
    """Delete request.

    DelRequest ::= [APPLICATION 10] LDAPDN
    """

    PROTOCOL_OP: ClassVar[int] = 10

    entry: str

    @classmethod
    def from_data(cls, data):  # noqa: D102
        return cls(entry=data)

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[DeleteResponse, None]:
        """Delete request handler."""
        if not ldap_session.user:
            yield DeleteResponse(**BAD_SEARCH_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield DeleteResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        base_dn = await get_base_dn()
        obj = self.entry.lower().removesuffix(
            ',' + base_dn.lower()).split(',')
        search_path = reversed(obj)

        query = select(Directory)\
            .join(Directory.path)\
            .options(selectinload(Directory.paths))\
            .filter(Path.path == search_path)

        obj = await session.scalar(query)
        if not obj:
            yield DeleteResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        await session.delete(obj)
        await session.commit()

        yield DeleteResponse(result_code=LDAPCodes.SUCCESS)


class ModifyDNRequest(BaseRequest):
    """Update DN.

    ```
    ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
        entry           LDAPDN,
        newrdn          RelativeLDAPDN,
        deleteoldrdn    BOOLEAN,
        newSuperior     [0] LDAPDN OPTIONAL
    }
    ```

    entry — The current DN for the target entry.
    newrdn — The new RDN to use assign to the entry. It may be the same as the
        current RDN if you only intend to move the entry beneath a new parent.
        If the new RDN includes any attribute values that arent
        already in the entry, the entry will be updated to include them.
    deleteoldrdn — Indicates whether to delete any attribute values from the
        entry that were in the original RDN but not in the new RDN.
    newSuperior — The DN of the entry that should become the new
        parent for the entry (and any of its subordinates).
        This is optional, and if it is omitted, then the entry will be
        left below the same parent and only the RDN will be altered.

    example:
        entry='cn=main,dc=multifactor,dc=dev'
        newrdn='cn=main2'
        deleteoldrdn=True
        new_superior='dc=multifactor,dc=dev'
    """

    PROTOCOL_OP: ClassVar[int] = 12

    entry: str
    newrdn: str
    deleteoldrdn: bool
    new_superior: str

    @classmethod
    def from_data(cls, data):
        """Create structure from ASN1Row dataclass list."""
        return cls(
            entry=data[0].value,
            newrdn=data[1].value,
            deleteoldrdn=data[2].value,
            new_superior=data[3].value,
        )

    async def handle(self, ldap_session: Session, session: AsyncSession) ->\
            AsyncGenerator[ModifyDNResponse, None]:
        """Handle message with current user."""
        base_dn = await get_base_dn()
        obj = self.entry.lower().removesuffix(
            ',' + base_dn.lower()).split(',')

        query = select(Directory)\
            .join(Directory.path)\
            .options(selectinload(Directory.paths))\
            .filter(Path.path == reversed(obj))

        new_sup = self.new_superior.lower().removesuffix(
            ',' + base_dn.lower()).split(',')

        new_sup_query = select(Directory)\
            .join(Directory.path)\
            .options(selectinload(Directory.path))\
            .filter(Path.path == reversed(new_sup))

        directory = await session.scalar(query)

        if not directory:
            yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        dn_is_base = self.new_superior.lower() == base_dn.lower()
        if dn_is_base:
            new_directory = Directory(
                object_class='',
                name=self.newrdn.split('=')[1],
            )
            new_path = new_directory.create_path()
        else:
            new_base_directory = await session.scalar(new_sup_query)
            if not new_base_directory:
                yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
                return

            new_directory = Directory(
                object_class='',
                name=self.newrdn.split('=')[1],
                parent=new_base_directory,
            )
            new_path = new_directory.create_path(new_base_directory)

        async with session.begin_nested():
            session.add_all([new_directory, new_path])
            await session.commit()

        async with session.begin_nested():
            await session.execute(
                update(Directory)
                .where(Directory.parent == directory)
                .values(parent_id=new_directory.id))

            q = update(Path)\
                .values({Path.path[directory.depth + 1]: self.newrdn})\
                .where(Path.directories.any(id=directory.id))

            from sqlalchemy.dialects import postgresql

            logger.debug(q.compile(
                dialect=postgresql.dialect(),  # type: ignore
                compile_kwargs={"literal_binds": True}))  # noqa

            await session.execute(
                q, execution_options={"synchronize_session": 'fetch'})

            await session.commit()

        async with session.begin_nested():
            await session.execute(
                update(Attribute)
                .where(Attribute.directory == directory)
                .values(directory_id=new_directory.id))
            await session.commit()

        await session.delete(directory)

        yield ModifyDNResponse(result_code=LDAPCodes.SUCCESS)


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

    async def handle(self, ldap_session: Session, session: AsyncSession):
        """Handle message with current user."""
        await asyncio.sleep(0)
        return
        yield


class ExtendedRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 23


protocol_id_map: dict[int, type[BaseRequest]] = \
    {request.PROTOCOL_OP: request  # type: ignore
        for request in BaseRequest.__subclasses__()}

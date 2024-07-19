"""Simple server for executing krb5 commands.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import logging
import os
import uuid
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import datetime, timedelta
from tempfile import gettempdir
from types import TracebackType
from typing import Annotated, AsyncIterator, Protocol

import kadmin_local as kadmin
from fastapi import (
    APIRouter,
    Body,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask

logging.basicConfig(level=logging.INFO)


class KAdminProtocol(Protocol):
    """Stub for kadmin.KAdmin."""


class PrincipalProtocol(Protocol):
    """Stub for kadmin.Principal."""


class ConfigSchema(BaseModel):
    """Main Config."""

    domain: str
    admin_dn: str
    krbadmin_dn: str
    services_dn: str
    krbadmin_password: str
    admin_password: str
    stash_password: str


class Principal(BaseModel):
    """Principal kadmin object."""

    kvno: int
    name: str
    failures: int
    last_failure: datetime | None
    last_pwd_change: datetime | None
    last_success: datetime | None
    maxrenewlife: timedelta
    mod_date: datetime
    pwexpire: datetime | None


class AbstractKRBManager(AbstractAsyncContextManager, ABC):
    """Kadmin manager."""

    class PrincipalNotFoundError(Exception):
        """Not found error."""

    @abstractmethod
    async def add_princ(
            self, name: str, password: str | None, **dbargs) -> None:
        """Create principal.

        :param str name: principal
        :param str | None password: if empty - uses randkey.
        """

    @abstractmethod
    async def get_princ(self, name: str) -> Principal | None:
        """Get principal.

        :param str name: principal
        :return kadmin.Principal: Principal
        """

    @abstractmethod
    async def change_password(self, name: str, new_password: str) -> None:
        """Chanage principal's password.

        :param str name: principal
        :param str new_password: ...
        """

    @abstractmethod
    async def create_or_update_princ_pw(self, name: str, new_password) -> None:
        """Create new principal or update password.

        :param str name: principal
        :param _type_ new_password: pw
        """

    @abstractmethod
    async def del_princ(self, name: str) -> None:
        """Delete principal by name.

        :param str name: principal
        """

    @abstractmethod
    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename principal.

        :param str name: original name
        :param str new_name: new name
        """

    @abstractmethod
    async def ktadd(self, names: list[str], fn: str) -> None:
        """Create or write to keytab.

        :param str name: principal
        :param str fn: filename
        """


class KAdminLocalManager(AbstractKRBManager):
    """Kadmin manager."""

    client: KAdminProtocol

    def __init__(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Create threadpool and get loop."""
        self.loop = loop or asyncio.get_running_loop()

    async def __aenter__(self) -> "KAdminLocalManager":
        """Create threadpool for kadmin client."""
        self.pool = ThreadPoolExecutor(max_workers=500).__enter__()
        self.client = await self._init_client()
        logging.info('Successfully connected to kadmin local')
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Destroy threadpool."""
        self.pool.__exit__(exc_type, exc, tb)

    async def _init_client(self) -> KAdminProtocol:
        """Init kadmin local connection."""
        return await self.loop.run_in_executor(self.pool, kadmin.local)

    async def add_princ(
            self, name: str, password: str | None, **dbargs) -> None:
        """Create principal.

        :param str name: principal
        :param str | None password: if empty - uses randkey.
        """
        await self.loop.run_in_executor(
            self.pool,
            self.client.add_principal, name, password)

    async def _get_raw_principal(self, name: str) -> PrincipalProtocol:
        principal = await self.loop.run_in_executor(
            self.pool, self.client.getprinc, name)

        if not principal:
            raise self.PrincipalNotFoundError(f'{name} not found')

        return principal

    async def get_princ(self, name: str) -> Principal:
        """Get principal.

        :param str name: principal
        :return kadmin.Principal: Principal
        """
        principal = await self._get_raw_principal(name)
        return Principal.model_validate(principal, from_attributes=True)

    async def change_password(self, name: str, new_password: str) -> None:
        """Chanage principal's password.

        :param str name: principal
        :param str new_password: ...
        """
        princ = await self._get_raw_principal(name)
        await self.loop.run_in_executor(
            self.pool, princ.change_password, new_password)

    async def create_or_update_princ_pw(self, name: str, new_password) -> None:
        """Create new principal or update password.

        :param str name: principal
        :param _type_ new_password: ...
        """
        try:
            await self.change_password(name, new_password)
        except self.PrincipalNotFoundError:
            await self.add_princ(name, new_password)

    async def del_princ(self, name: str) -> None:
        """Delete principal by name.

        :param str name: principal
        """
        await self.loop.run_in_executor(
            self.pool, self.client.delprinc, name)

    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename principal.

        :param str name: original name
        :param str new_name: new name
        """
        await self.loop.run_in_executor(
            self.pool, self.client.rename_principal, name, new_name)

    async def ktadd(self, names: list[str], fn: str) -> None:
        """Create or write to keytab.

        :param str name: principal
        :param str fn: filename
        :raises self.PrincipalNotFoundError: on not found princ
        """
        principals = [await self._get_raw_principal(name) for name in names]
        if not all(principals):
            raise self.PrincipalNotFoundError

        for princ in principals:
            await self.loop.run_in_executor(
                self.pool, princ.ktadd, fn)


@asynccontextmanager
async def kadmin_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create kadmin instance."""
    try:
        async with KAdminLocalManager() as kadmind:
            app.state.kadmind = kadmind
            yield
    except Exception:
        yield


def get_kadmin() -> KAdminLocalManager:
    """Stub."""
    raise NotImplementedError


def handle_db_error(request: Request, exc: BaseException):
    """Handle duplicate."""
    raise HTTPException(
        status.HTTP_424_FAILED_DEPENDENCY, detail='Database Error')


def handle_duplicate(request: Request, exc: BaseException):
    """Handle duplicate."""
    raise HTTPException(
        status.HTTP_409_CONFLICT, detail='Principal already exists')


def handle_not_found(request: Request, exc: BaseException):
    """Handle duplicate."""
    raise HTTPException(
        status.HTTP_404_NOT_FOUND, detail='Principal does not exist')


setup_router = APIRouter(prefix='/setup')
principal_router = APIRouter(prefix='/principal')


@setup_router.post('/configs', status_code=status.HTTP_201_CREATED)
def write_configs(
    krb5_config: Annotated[str, Body()],
    kdc_config: Annotated[str, Body()],
) -> None:
    """Write two config files, strings are: hex bytes.

    :param Annotated[str, Body krb5_config: krb5 hex bytes format config
    :param Annotated[str, Body kdc_config: kdc hex bytes format config
    """
    with open('/etc/krb5.conf', 'wb') as f:
        f.write(bytes.fromhex(krb5_config))

    with open('/etc/kdc.conf', 'wb') as f:
        f.write(bytes.fromhex(kdc_config))


@setup_router.post('/stash', status_code=201)
async def run_setup_stash(schema: ConfigSchema) -> None:
    """Set up stash file."""
    proc = await asyncio.create_subprocess_exec(
        "kdb5_ldap_util",
        "-D", schema.admin_dn,
        "stashsrvpw", "-f", "/etc/krb5.d/stash.keyfile", schema.krbadmin_dn,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    data = b'\n'.join([
        schema.admin_password.encode(),
        schema.krbadmin_password.encode(),
        schema.krbadmin_password.encode(),
    ]) + b'\n'

    logging.info(await proc.communicate(input=data))

    if await proc.wait() != 0:
        raise HTTPException(status.HTTP_409_CONFLICT, 'failed stash')


@setup_router.post('/subtree', status_code=201)
async def run_setup_subtree(schema: ConfigSchema) -> None:
    """Set up subtree in ldap.

    :param ConfigSchema schema: _description_
    :raises HTTPException: _description_
    """
    create_proc = await asyncio.create_subprocess_exec(
        "kdb5_ldap_util", "-D", schema.admin_dn,
        "create", "-subtrees", schema.services_dn,
        "-r", schema.domain.upper(), "-s",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    data = b'\n'.join([
        schema.admin_password.encode(),
        schema.stash_password.encode(),
        schema.stash_password.encode(), b'',
    ])
    stdin, stderr = await create_proc.communicate(input=data)

    logging.info(stdin)
    logging.info(stderr)
    if await create_proc.wait() != 0:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, stderr.decode())


@principal_router.post('', response_class=Response, status_code=201)
async def add_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    password: Annotated[str | None, Body(embed=True)] = None,
) -> None:
    """Add principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body password: principal password
    """
    await kadmin.add_princ(name, password)


@principal_router.get('')
async def get_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: str,
) -> Principal:
    """Add principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body password: principal password
    """
    return await kadmin.get_princ(name)


@principal_router.delete('')
async def del_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: str,
) -> None:
    """Add principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body password: principal password
    """
    await kadmin.del_princ(name)


@principal_router.patch('', status_code=201, response_class=Response)
async def change_princ_password(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    password: Annotated[str, Body()],
) -> None:
    """Change princ pw principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body password: principal password
    """
    await kadmin.change_password(name, password)


@principal_router.post(
    '/create_or_update', status_code=201, response_class=Response)
async def create_or_update_princ_password(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    password: Annotated[str, Body()],
) -> None:
    """Change princ pw principal or create with new.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body password: principal password
    """
    await kadmin.create_or_update_princ_pw(name, password)


@principal_router.put(
    '', status_code=status.HTTP_202_ACCEPTED,
    response_class=Response)
async def rename_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    new_name: Annotated[str, Body()],
) -> None:
    """Rename principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body new_name: principal new name
    """
    """"""
    await kadmin.rename_princ(name, new_name)


@principal_router.post('/ktadd')
async def ktadd(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    names: Annotated[list[str], Body()],
) -> FileResponse:
    """Ktadd principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body password: principal password
    """
    filename = os.path.join(gettempdir(), str(uuid.uuid1()))
    await kadmin.ktadd(names, filename)

    return FileResponse(
        filename,
        background=BackgroundTask(os.unlink, filename),
    )


@setup_router.get('/status')
def get_status(request: Request) -> bool:
    """Get kadmin status.

    true - is ready
    false - not set
    """
    kadmind = getattr(request.app.state, 'kadmind', None)

    if kadmind is not None:
        return True
    return False


def create_app() -> FastAPI:
    """Create FastAPI app."""
    app = FastAPI(
        name="KadminMultiDirectory",
        title="KadminMultiDirectory",
        lifespan=kadmin_lifespan,
    )

    def _get_kadmin() -> AbstractKRBManager:
        try:
            return app.state.kadmind
        except AttributeError:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)

    app.dependency_overrides = {
        get_kadmin: _get_kadmin,
    }
    app.add_middleware(
        CORSMiddleware,
        allow_credentials=True,
        allow_methods=["*"],
    )
    app.include_router(setup_router)
    app.include_router(principal_router)
    app.add_exception_handler(kadmin.KDBAccessError, handle_db_error)
    app.add_exception_handler(kadmin.DuplicateError, handle_duplicate)
    app.add_exception_handler(kadmin.KDBNoEntryError, handle_not_found)
    app.add_exception_handler(
        AbstractKRBManager.PrincipalNotFoundError, handle_not_found)
    return app

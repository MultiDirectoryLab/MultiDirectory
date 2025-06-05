"""Simple server for executing krb5 commands.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import logging
import os
import shutil
import uuid
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from functools import partial
from tempfile import gettempdir
from types import TracebackType
from typing import Annotated, AsyncIterator, Protocol, Self

import kadmin_local as kadmv  # type: ignore
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

KRB5_CONF_PATH = "/etc/krb5.conf"
KRB5_CONF_EXAMPLE_PATH = "/usr/local/share/examples/krb5/krb5.conf"
STASH_FILE_PATH = "/etc/krb5.d/stash.keyfile"

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


class PrincipalNotFoundError(Exception):
    """Not found error."""


class AbstractKRBManager(ABC):
    """Kadmin manager."""

    @abstractmethod
    async def connect(self) -> Self:
        """Connect."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect."""

    @abstractmethod
    async def add_princ(
        self,
        name: str,
        password: str | None,
        **dbargs,
    ) -> None:
        """Create principal.

        Args:
            name (str): principal name
            password (str | None): password, if empty - uses randkey.
            **dbargs: database arguments
        """

    @abstractmethod
    async def get_princ(self, name: str) -> Principal | None:
        """Get principal.

        Args:
            name (str): principal name

        Returns:
            Principal | None:
        """

    @abstractmethod
    async def change_password(self, name: str, new_password: str) -> None:
        """Chanage principal's password.

        Args:
            name (str): principal name
            new_password (str): password
        """

    @abstractmethod
    async def create_or_update_princ_pw(
        self,
        name: str,
        new_password: str,
    ) -> None:
        """Create new principal or update password.

        Args:
            name (str): principal name
            new_password (str): password
        """

    @abstractmethod
    async def del_princ(self, name: str) -> None:
        """Delete principal by name.

        Args:
            name (str): principal name
        """

    @abstractmethod
    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename principal.

        Args:
            name (str): principal name
            new_name (str): new principal name
        """

    @abstractmethod
    async def ktadd(self, names: list[str], fn: str) -> None:
        """Create or write to keytab.

        Args:
            names (list[str]): principal names
            fn (str): file name
        """

    @abstractmethod
    async def lock_princ(self, name: str, **dbargs) -> None:
        """Lock principal.

        Args:
            name (str): principal name
            **dbargs: database arguments
        """

    @abstractmethod
    async def force_pw_principal(self, name: str, **dbargs) -> None:
        """Force password principal.

        Args:
            name (str): principal name
            **dbargs: database arguments
        """


class KAdminLocalManager(AbstractKRBManager):
    """Kadmin manager."""

    client: KAdminProtocol

    def __init__(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Create threadpool and get loop.

        Args:
            loop (asyncio.AbstractEventLoop | None): event loop
        """
        self.loop = loop or asyncio.get_running_loop()

    async def connect(self) -> Self:
        """Create threadpool for kadmin client.

        Returns:
            KAdminLocalManager:
        """
        self.pool = ThreadPoolExecutor(max_workers=500).__enter__()
        self.client = await asyncio.wait_for(self._init_client(), 40)
        return self

    async def disconnect(self) -> None:
        """Destroy threadpool."""
        del self.client
        self.pool.__exit__(None, None, None)

    async def __aenter__(self) -> Self:
        """Create threadpool for kadmin client."""
        await self.connect()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Destroy threadpool.

        Args:
            exc_type (type[BaseException] | None): exception type
            exc (BaseException | None): exception
            tb (TracebackType | None): traceback
        """
        await self.disconnect()

    async def _init_client(self) -> KAdminProtocol:
        """Init kadmin local connection.

        Returns:
            KAdminProtocol:
        """
        return await self.loop.run_in_executor(self.pool, kadmv.local)

    async def add_princ(
        self,
        name: str,
        password: str | None,
        **dbargs,
    ) -> None:
        """Create principal.

        Args:
            name (str): principal name
            password (str): password, if empty - uses randkey.
            **dbargs: database arguments
        """
        await self.loop.run_in_executor(
            self.pool,
            self.client.add_principal,
            name,
            password,
        )

        if password:
            # NOTE: add preauth, attributes == krbticketflags
            princ = await self._get_raw_principal(name)
            await self.loop.run_in_executor(
                self.pool,
                partial(princ.modify, attributes=128),
            )

    async def _get_raw_principal(self, name: str) -> PrincipalProtocol:
        principal = await self.loop.run_in_executor(
            self.pool,
            self.client.getprinc,
            name,
        )

        if not principal:
            raise PrincipalNotFoundError(f"{name} not found")

        return principal

    async def get_princ(self, name: str) -> Principal:
        """Get principal.

        Args:
            name (str): principal name

        Returns:
            Principal: Principal kadmin object
        """
        principal = await self._get_raw_principal(name)
        return Principal.model_validate(principal, from_attributes=True)

    async def change_password(self, name: str, new_password: str) -> None:
        """Chanage principal's password.

        Args:
            name (str): principal name
            new_password (str): password
        """
        princ = await self._get_raw_principal(name)
        await self.loop.run_in_executor(
            self.pool,
            princ.change_password,
            new_password,
        )

    async def create_or_update_princ_pw(
        self,
        name: str,
        new_password: str,
    ) -> None:
        """Create new or update password principal.

        Args:
            name (str): principal name
            new_password (str): password
        """
        try:
            await self.change_password(name, new_password)
        except PrincipalNotFoundError:
            await self.add_princ(name, new_password)

    async def del_princ(self, name: str) -> None:
        """Delete principal by name.

        Args:
            name (str): principal name
        """
        await self.loop.run_in_executor(self.pool, self.client.delprinc, name)

    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename principal.

        Args:
            name (str): Principal name.
            new_name (str): Principal new name.
        """
        await self.loop.run_in_executor(
            self.pool,
            self.client.rename_principal,
            name,
            new_name,
        )

    async def ktadd(self, names: list[str], fn: str) -> None:
        """Create or write to keytab.

        Args:
            names (list[str]): principal names
            fn (str): file name

        Raises:
            PrincipalNotFoundError: Principal not found
        """
        principals = [await self._get_raw_principal(name) for name in names]
        if not all(principals):
            raise PrincipalNotFoundError("Principal not found")

        for princ in principals:
            await self.loop.run_in_executor(self.pool, princ.ktadd, fn)

    async def lock_princ(self, name: str, **dbargs) -> None:
        """Lock princ.

        Args:
            name (str): principal names
            **dbargs: database arguments
        """
        princ = await self._get_raw_principal(name)
        princ.expire = "Now"
        await self.loop.run_in_executor(self.pool, princ.commit)

    async def force_pw_principal(self, name: str, **dbargs) -> None:
        """Force password principal.

        Args:
            name (str): principal names
            **dbargs: database arguments
        """
        princ = await self._get_raw_principal(name)
        princ.pwexpire = "Now"
        await self.loop.run_in_executor(self.pool, princ.commit)


@asynccontextmanager
async def kadmin_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create kadmin instance.

    Args:
        app (FastAPI): FastAPI app

    Yields:
        AsyncIterator[None]: Async iterator
    """
    loop = asyncio.get_running_loop()

    async def try_set_kadmin(app: FastAPI) -> None:
        logging.info("Trying to initialize ldap connect...")

        while not getattr(app.state, "kadmin", None):
            try:
                app.state.kadmind = await KAdminLocalManager().connect()
            except (kadmv.KAdminError, TimeoutError):
                await asyncio.sleep(1)
            else:
                logging.info("Successfully connected to kadmin local")
                return

    await loop.create_task(try_set_kadmin(app))
    yield
    if kadmind := getattr(app.state, "kadmind", None):
        await kadmind.disconnect()
        delattr(app.state, "kadmind")
        logging.info("Successfully shutted down kadmin local")


def get_kadmin() -> KAdminLocalManager:
    """Stub.

    Raises:
        NotImplementedError: NotImplementedError
    """
    raise NotImplementedError


def handle_db_error(request: Request, exc: BaseException):  # noqa: ARG001
    """Handle duplicate.

    Args:
        request (Request): request
        exc (BaseException): exception

    Raises:
        HTTPException: Database Error
    """
    raise HTTPException(
        status.HTTP_424_FAILED_DEPENDENCY,
        detail="Database Error",
    )


def handle_duplicate(request: Request, exc: BaseException):  # noqa: ARG001
    """Handle duplicate.

    Args:
        request (Request): request
        exc (BaseException): exception

    Raises:
        HTTPException: Principal already exists
    """
    raise HTTPException(
        status.HTTP_409_CONFLICT,
        detail="Principal already exists",
    )


def handle_not_found(request: Request, exc: BaseException):  # noqa: ARG001
    """Handle duplicate.

    Args:
        request (Request): request
        exc (BaseException): exception

    Raises:
        HTTPException: Principal does not exist
    """
    raise HTTPException(
        status.HTTP_404_NOT_FOUND,
        detail="Principal does not exist",
    )


setup_router = APIRouter(prefix="/setup", tags=["setup"])
principal_router = APIRouter(prefix="/principal", tags=["config"])


@setup_router.post("/configs", status_code=status.HTTP_201_CREATED)
def write_configs(
    krb5_config: Annotated[str, Body()],
    kdc_config: Annotated[str, Body()],
) -> None:
    """Write two config files, strings are: hex bytes.

    Args:
        krb5_config (str): krb5 hex bytes format config.
        kdc_config (str): kdc hex bytes format config.
    """
    with open("/etc/krb5.conf", "wb") as f:
        f.write(bytes.fromhex(krb5_config))

    with open("/etc/kdc.conf", "wb") as f:
        f.write(bytes.fromhex(kdc_config))


@setup_router.post("/stash", status_code=201)
async def run_setup_stash(schema: ConfigSchema) -> None:
    """Set up stash file.

    Args:
        schema (ConfigSchema): Configuration schema for stash setup.

    Raises:
        HTTPException: Failed stash
    """
    proc = await asyncio.create_subprocess_exec(
        "kdb5_ldap_util",
        "-D",
        schema.admin_dn,
        "stashsrvpw",
        "-f",
        STASH_FILE_PATH,
        schema.krbadmin_dn,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    data = (
        b"\n".join(
            [
                schema.admin_password.encode(),
                schema.krbadmin_password.encode(),
                schema.krbadmin_password.encode(),
            ],
        )
        + b"\n"
    )

    logging.info(await proc.communicate(input=data))

    if await proc.wait() != 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "failed stash")


@setup_router.post("/subtree", status_code=201)
async def run_setup_subtree(schema: ConfigSchema) -> None:
    """Set up subtree in ldap.

    Args:
        schema (ConfigSchema): Configuration schema for subtree setup.

    Raises:
        HTTPException: If setup fails.
    """
    create_proc = await asyncio.create_subprocess_exec(
        "kdb5_ldap_util",
        "-D",
        schema.admin_dn,
        "create",
        "-subtrees",
        schema.services_dn,
        "-r",
        schema.domain.upper(),
        "-s",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    data = b"\n".join(
        [
            schema.admin_password.encode(),
            schema.stash_password.encode(),
            schema.stash_password.encode(),
            b"",
        ],
    )
    stdin, stderr = await create_proc.communicate(input=data)

    logging.info(stdin)
    logging.info(stderr)
    if await create_proc.wait() != 0:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, stderr.decode())

    with open("/etc/krb5kdc/kadm5.acl", "w") as f:
        f.write(f"*/admin@{schema.domain.upper()}        *\n")


@setup_router.post("/reset")
async def reset_setup() -> None:
    """Reset setup."""
    if os.path.exists(KRB5_CONF_PATH):
        os.remove(KRB5_CONF_PATH)
        shutil.copy(KRB5_CONF_EXAMPLE_PATH, KRB5_CONF_PATH)

    if os.path.exists(STASH_FILE_PATH):
        os.remove(STASH_FILE_PATH)


@principal_router.post("", response_class=Response, status_code=201)
async def add_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    password: Annotated[str | None, Body(embed=True)] = None,
) -> None:
    """Add principal.

    Args:
        kadmin (AbstractKRBManager): Kadmin abstract manager.
        name (str): Principal name.
        password (str | None): Principal password.
    """
    await kadmin.add_princ(name, password)


@principal_router.get("")
async def get_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: str,
) -> Principal:
    """Get principal.

    Args:
        kadmin (AbstractKRBManager): Kadmin abstract manager.
        name (str): Principal name.

    Returns:
        Principal: Principal object.
    """
    return await kadmin.get_princ(name)


@principal_router.delete("")
async def del_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: str,
) -> None:
    """Delete principal.

    Args:
        kadmin (AbstractKRBManager): Kadmin abstract manager.
        name (str): Principal name.
    """
    await kadmin.del_princ(name)


@principal_router.patch("", status_code=201, response_class=Response)
async def change_princ_password(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    password: Annotated[str, Body()],
) -> None:
    """Change principal password.

    Args:
        kadmin (AbstractKRBManager): Kadmin abstract manager.
        name (str): Principal name.
        password (str): Principal password.
    """
    await kadmin.change_password(name, password)


@principal_router.post(
    "/create_or_update",
    status_code=201,
    response_class=Response,
)
async def create_or_update_princ_password(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    password: Annotated[str, Body()],
) -> None:
    """Change principal password or create with new.

    Args:
        kadmin (AbstractKRBManager): Kadmin abstract manager.
        name (str): Principal name.
        password (str): Principal password.
    """
    await kadmin.create_or_update_princ_pw(name, password)


@principal_router.put(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_class=Response,
)
async def rename_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    new_name: Annotated[str, Body()],
) -> None:
    """Rename principal.

    Args:
        kadmin (AbstractKRBManager): Kadmin abstract manager.
        name (str): Principal name.
        new_name (str): Principal new name.
    """
    await kadmin.rename_princ(name, new_name)


@principal_router.post("/ktadd")
async def ktadd(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    names: Annotated[list[str], Body()],
) -> FileResponse:
    """Ktadd principal.

    Args:
        kadmin (AbstractKRBManager): Kadmin abstract manager.
        names (list[str]): List of principal names.

    Returns:
        FileResponse: Keytab file response.
    """
    filename = os.path.join(gettempdir(), str(uuid.uuid1()))
    await kadmin.ktadd(names, filename)

    return FileResponse(
        filename,
        background=BackgroundTask(os.unlink, filename),
    )


@principal_router.post("/lock", response_class=Response)
async def lock_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body(embed=True)],
) -> None:
    """Lock principal.

    Args:
        kadmin (AbstractKRBManager): Kadmin abstract manager.
        name (str): Principal name.
    """
    await kadmin.lock_princ(name)


@principal_router.post("/force_reset", response_class=Response)
async def force_pw_reset_principal(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body(embed=True)],
) -> None:
    """Mark principal as password expired.

    Args:
        kadmin (AbstractKRBManager): Kadmin abstract manager.
        name (str): Principal name.
    """
    await kadmin.force_pw_principal(name)


@setup_router.get("/status")
def get_status(request: Request) -> bool:
    """Get kadmin status.

    true - is ready
    false - not set

    Args:
        request (Request): http request

    Returns:
        bool
    """
    kadmind = getattr(request.app.state, "kadmind", None)

    return kadmind is not None


def create_app() -> FastAPI:
    """Create FastAPI app.

    Returns:
        FastAPI: web app
    """
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
    app.add_exception_handler(kadmv.KDBAccessError, handle_db_error)
    app.add_exception_handler(kadmv.DuplicateError, handle_duplicate)
    app.add_exception_handler(kadmv.KDBNoEntryError, handle_not_found)
    app.add_exception_handler(PrincipalNotFoundError, handle_not_found)
    return app

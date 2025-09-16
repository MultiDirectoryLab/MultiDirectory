"""Utils for kadmin."""

from functools import wraps
from typing import Any, Callable

import httpx
from loguru import logger as loguru_logger
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from enums import StrEnum
from entities import Attribute, CatalogueSetting, Directory, EntityType
from repo.pg.tables import queryable_attr as qa

from .exceptions import KRBAPIError

KERBEROS_STATE_NAME = "KerberosState"
log = loguru_logger.bind(name="kadmin")

log.add(
    "logs/kadmin_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "kadmin",
    retention="10 days",
    rotation="1d",
    colorize=False,
)


class KerberosState(StrEnum):
    """KRB state enum."""

    NOT_CONFIGURED = "0"
    READY = "1"
    WAITING_FOR_RELOAD = "2"


def logger_wraps(is_stub: bool = False) -> Callable:
    """Log kadmin calls.

    :param bool is_stub: flag to change logs, defaults to False
    :return Callable: any method
    """

    def wrapper(func: Callable) -> Callable:
        name = func.__name__
        bus_type = " stub " if is_stub else " "

        @wraps(func)
        async def wrapped(*args: str, **kwargs: str) -> Any:
            logger = log.opt(depth=1)
            try:
                principal = args[1]
            except IndexError:
                principal = kwargs.get("name", "")

            logger.info(f"Calling{bus_type}'{name}' for {principal}")
            try:
                result = await func(*args, **kwargs)
            except (httpx.ConnectError, httpx.TimeoutException):
                logger.critical("Can not access kadmin server!")
                raise KRBAPIError

            except KRBAPIError as err:
                logger.error(f"{name} call raised: {err}")
                raise

            else:
                if not is_stub:
                    logger.success(f"Executed {name}")
            return result

        return wrapped

    return wrapper


async def set_state(session: AsyncSession, state: "KerberosState") -> None:
    """Set the server state in the database.

    This function updates the server state in the database by either adding
    a new entry, updating an existing entry, or deleting and re-adding the
    entry if there are multiple entries found.
    """
    results = await session.execute(
        select(CatalogueSetting)
        .filter_by(name = KERBEROS_STATE_NAME),
    )  # fmt: skip
    kerberos_state = results.scalar_one_or_none()

    if not kerberos_state:
        session.add(CatalogueSetting(name=KERBEROS_STATE_NAME, value=state))
        return

    await session.execute(
        update(CatalogueSetting)
        .filter_by(name=KERBEROS_STATE_NAME)
        .values(value=state),
    )


async def get_krb_server_state(session: AsyncSession) -> "KerberosState":
    """Get kerberos server state."""
    state = await session.scalar(
        select(CatalogueSetting)
        .filter_by(name=KERBEROS_STATE_NAME),
    )  # fmt: skip

    if state is None:
        return KerberosState.NOT_CONFIGURED
    return KerberosState(state.value)


async def unlock_principal(name: str, session: AsyncSession) -> None:
    """Unlock principal.

    :param str name: upn
    :param AsyncSession session: db
    """
    subquery = (
        select(qa(Directory.id))
        .outerjoin(qa(Directory.entity_type))
        .where(
            qa(Directory.name).ilike(name),
            qa(EntityType.name) == "KRB Principal",
        )
        .scalar_subquery()
    )
    await session.execute(
        delete(Attribute)
        .filter_by(directory_id=subquery, name="krbprincipalexpiration")
        .execution_options(synchronize_session=False),
    )

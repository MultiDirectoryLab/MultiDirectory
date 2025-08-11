"""Utils for kadmin."""

from functools import wraps
from typing import Any, Callable

import httpx
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import Attribute, CatalogueSetting, Directory, EntityType

from .base import KERBEROS_STATE_NAME, KerberosState, KRBAPIError, log


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
            except (httpx.ConnectError, httpx.ConnectTimeout):
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
        .where(CatalogueSetting.name == KERBEROS_STATE_NAME),
    )  # fmt: skip
    kerberos_state = results.scalar_one_or_none()

    if not kerberos_state:
        session.add(CatalogueSetting(name=KERBEROS_STATE_NAME, value=state))
        return

    await session.execute(
        update(CatalogueSetting)
        .where(CatalogueSetting.name == KERBEROS_STATE_NAME)
        .values(value=state),
    )


async def get_krb_server_state(session: AsyncSession) -> "KerberosState":
    """Get kerberos server state."""
    state = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == KERBEROS_STATE_NAME),
    )  # fmt: skip

    if state is None:
        return KerberosState.NOT_CONFIGURED
    return KerberosState(state.value)


async def unlock_principal(name: str, session: AsyncSession) -> None:
    """Unlock principal.

    :param str name: upn
    :param AsyncSession session: db
    """
    entity_type_query = (
        select(EntityType.id)
        .where(EntityType.name == "User")
        .scalar_subquery()
    )
    subquery = (
        select(Directory.id)
        .where(
            Directory.name.ilike(name),
            Directory.entity_type_id == entity_type_query,
        )
        .scalar_subquery()
    )
    await session.execute(
        delete(Attribute)
        .where(
            Attribute.directory_id == subquery,
            Attribute.name == "krbprincipalexpiration",
        )
        .execution_options(synchronize_session=False),
    )

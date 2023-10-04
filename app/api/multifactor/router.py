"""Network policies."""

import operator
from typing import Annotated

from fastapi import Body, Depends, status
from fastapi.routing import APIRouter
from sqlalchemy import delete

from api.auth import User, get_current_user
from models.database import AsyncSession, get_session
from models.ldap3 import CatalogueSetting

mfa_router = APIRouter(prefix='/multifactor')


@mfa_router.post('/setup', status_code=status.HTTP_201_CREATED)
async def setup_mfa(
    mfa_key: Annotated[str, Body()],
    mfa_secret: Annotated[str, Body()],
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> bool:
    """Set mfa credentials, rewrites if exists.

    :param str mfa_key: multifactor key
    :param str mfa_secret: multifactor api secret
    :return bool: status
    """
    async with session.begin_nested():
        await session.execute((
            delete(CatalogueSetting)
            .filter(operator.or_(
                CatalogueSetting.name == 'mfa_key',
                CatalogueSetting.name == 'mfa_secret',
            ))
        ))
        await session.flush()
        session.add(CatalogueSetting(name='mfa_key', value=mfa_key))
        session.add(CatalogueSetting(name='mfa_secret', value=mfa_secret))
        await session.commit()

    return True

"""Network policies."""

import asyncio
import operator
from json import JSONDecodeError
from typing import Annotated

from fastapi import (
    Body,
    Depends,
    Form,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.routing import APIRouter
from jose import JWTError, jwt
from jose.exceptions import JWKError
from loguru import logger
from pydantic import ValidationError
from sqlalchemy import delete

from api.auth import User, get_current_user
from config import get_queue_pool
from ldap_protocol.multifactor import Creds, MultifactorAPI, get_auth
from models.database import AsyncSession, get_session
from models.ldap3 import CatalogueSetting
from models.ldap3 import User as DBUser

from .oauth2 import authenticate_user
from .schema import Login

mfa_router = APIRouter(prefix='/multifactor')


@mfa_router.post('/setup', status_code=status.HTTP_201_CREATED)
async def setup_mfa(
    mfa_key: Annotated[str, Body()],
    mfa_secret: Annotated[str, Body()],
    is_ldap_scope: Annotated[bool, Body()] = True,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> bool:
    """Set mfa credentials, rewrites if exists.

    :param str mfa_key: multifactor key
    :param Annotated[bool, Body is_ldap_scope: _description_, defaults to True
    :param str mfa_secret: multifactor api secret
    :return bool: status
    """
    if is_ldap_scope:
        key_name = 'mfa_key_ldap'
        secret_name = 'mfa_secret_ldap'  # noqa
    else:
        key_name = 'mfa_key'
        secret_name = 'mfa_secret'  # noqa

    async with session.begin_nested():
        await session.execute((
            delete(CatalogueSetting)
            .filter(operator.or_(
                CatalogueSetting.name == key_name,
                CatalogueSetting.name == secret_name,
            ))
        ))
        await session.flush()
        session.add(CatalogueSetting(name=key_name, value=mfa_key))
        session.add(CatalogueSetting(name=secret_name, value=mfa_secret))
        await session.commit()

    return True


@mfa_router.post('/create', name='callback_mfa', include_in_schema=False)
async def callback_mfa(
    access_token: Annotated[str, Form(alias='accessToken')],
    pool: dict[str, asyncio.Queue[str]] = Depends(get_queue_pool),
    session: AsyncSession = Depends(get_session),
    mfa_creds: Creds | None = Depends(get_auth),
) -> bool:
    """Disassemble mfa token and send it to websocket.

    Callback endpoint for MFA.

    :param Annotated[str, Form access_token: access token from multifactor
    :param str | None mfa_secret: multifactor secret from settings
    :raises HTTPException: 404
    :return bool: status
    """
    if not mfa_creds:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    try:
        payload = jwt.decode(
            access_token, mfa_creds.secret, audience=mfa_creds.key)
    except (JWTError, AttributeError, JWKError):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY)

    user_id: str = payload.get("uid")
    if user_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    user = await session.get(DBUser, int(user_id))

    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    queue = pool.get(user.display_name)
    if not queue:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    await queue.put(access_token)

    return True


@mfa_router.websocket('/connect')
async def two_factor_protocol(
    websocket: WebSocket,
    session: AsyncSession = Depends(get_session),
    api: MultifactorAPI = Depends(MultifactorAPI.from_di),
    pool: dict[str, asyncio.Queue[str]] = Depends(get_queue_pool),
) -> None:
    """Authenticate with two factor app.

    Protocol description:
    1. Sends `{'status': 'connected', 'message': ''}`;
    2. Recieves json `{'username': 'un', 'password': 'pwd'}`;
    3. Sends `{'status': 'pending', 'message': 'https://example.com'}`
        where message is an any redirect url;
    4. Websocket goes to pending state and waits for MFA api callback send;
    5. Sends `{'status': 'success', 'message': token}` where token is
        a mfa access and refresh token;

    :param WebSocket websocket: websocket
    :param MultifactorAPI api: MF API, depends
    :param dict[str, Queue[str]] pool: queue pool for async comms, depends
    """
    await websocket.accept()
    if not api:
        await websocket.close(
            status.WS_1002_PROTOCOL_ERROR, 'Missing API credentials')
        return

    await websocket.send_json({'status': 'connected', 'message': ''})

    try:
        creds = Login.model_validate(await websocket.receive_json())
        user = await authenticate_user(session, creds.username, creds.password)
    except (ValidationError, UnicodeDecodeError, JSONDecodeError):
        await websocket.close(
            status.WS_1007_INVALID_FRAME_PAYLOAD_DATA, 'Invalid data')
        return

    if not user:
        await websocket.close(
            status.WS_1002_PROTOCOL_ERROR, 'Invalid credentials')
        return

    try:
        redirect_url = await api.get_create_mfa(
            user.display_name, websocket.url_for('callback_mfa'), user.id)

    except MultifactorAPI.MultifactorError as err:
        logger.error(err.__traceback__)
        await websocket.close(
            status.WS_1013_TRY_AGAIN_LATER, 'Multifactor error')
        return

    await websocket.send_json({'status': 'pending', 'message': redirect_url})

    queue = asyncio.Queue(maxsize=1)
    pool[user.display_name] = queue

    try:
        token = await asyncio.wait_for(queue.get(), timeout=120)
    except TimeoutError:
        await websocket.close(
            status.WS_1013_TRY_AGAIN_LATER, 'To factor timeout')
        return
    except WebSocketDisconnect:
        logger.warning(f'Two factor interrupt for {user.display_name}')
        return
    finally:
        del pool[user.display_name]

    await websocket.send_json({'status': 'success', 'message': token})

    await websocket.close()

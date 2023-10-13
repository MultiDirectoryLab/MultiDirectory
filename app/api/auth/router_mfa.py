"""Network policies."""

import operator
from asyncio import Queue
from json import JSONDecodeError
from typing import Annotated

from fastapi import Body, Depends, Form, HTTPException, WebSocket, status
from fastapi.routing import APIRouter
from jose import JWTError, jwt
from pydantic import ValidationError
from sqlalchemy import delete

from api.auth import User, get_current_user
from config import get_queue_pool
from ldap_protocol.multifactor import MultifactorAPI
from models.database import AsyncSession, get_session
from models.ldap3 import CatalogueSetting
from models.ldap3 import User as DBUser

from .oauth2 import authenticate_user, get_mfa_secret
from .schema import Login

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
        get_mfa_secret.cache_clear()

    return True


@mfa_router.post('/create', name='callback_mfa')
async def callback_mfa(
    access_token: Annotated[str, Form()],
    pool: dict[str, Queue[str]] = Depends(get_queue_pool),
    session: AsyncSession = Depends(get_session),
    mfa_secret: str | None = Depends(get_mfa_secret),
) -> bool:
    """Disassemble mfa token and send it to websocket. Callback endpoint for MFA.

    :param Annotated[str, Form access_token: access token from multifactor
    :param str | None mfa_secret: multifactor secret from settings
    :raises HTTPException: 404
    :return bool: status
    """
    if not mfa_secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    try:
        payload = jwt.decode(access_token, mfa_secret)
    except (JWTError, AttributeError):
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    user = await session.get(DBUser, int(user_id))

    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    queue = pool.get(user.display_name)
    if not queue:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    await queue.put(user)

    return True


@mfa_router.websocket('/connect')
async def two_factor_protocol(
    websocket: WebSocket,
    session: AsyncSession = Depends(get_session),
    api: MultifactorAPI = Depends(MultifactorAPI.from_di),
    pool: dict[str, Queue[str]] = Depends(get_queue_pool),
):
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

    base_url = str(websocket.base_url)\
        .replace("wss://", "https://")\
        .replace("ws://", "http://")

    result = await api.get_create_mfa(
        user.display_name,
        base_url + mfa_router.url_path_for('callback_mfa'),
        str(user.id),
    )

    await websocket.send_json({'status': 'pending', 'message': result})

    queue = Queue(maxsize=1)
    pool[user.display_name] = queue

    token = await queue.get()

    del pool[user.display_name]
    await websocket.send_json({'status': 'success', 'message': token})

    await websocket.close()

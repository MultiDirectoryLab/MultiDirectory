"""OAuth modules."""

from datetime import datetime, timedelta
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from config import Settings, get_settings
from ldap_protocol.multifactor import Creds, get_auth
from ldap_protocol.utils import get_user
from models.database import AsyncSession, get_session
from models.ldap3 import User as DBUser
from security import verify_password

from .schema import User

_ALGORITHM = "HS256"

oauth2 = OAuth2PasswordBearer(tokenUrl="auth/token/get", auto_error=False)

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def authenticate_user(
    session: AsyncSession,
    username: str,
    password: str,
) -> User | None:
    """Get user and verify password.

    :param AsyncSession session: sa session
    :param str username: any str
    :param str password: any str
    :return User | None: User model (pydantic)
    """
    user = await get_user(session, username)
    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return User.from_db(user, access='access')


def create_token(
    uid: int,
    secret: str,
    expires_minutes: int,
    grant_type: Literal['refresh', 'access'],
    *, extra_data: dict | None = None,
) -> str:
    """Create jwt token.

    :param int uid: user id
    :param dict data: data dict
    :param str secret: secret key
    :param int expires_minutes: exire time in minutes
    :param Literal[refresh, access] grant_type: grant type flag
    :return str: jwt token
    """
    if not extra_data:
        extra_data = {}

    to_encode = extra_data.copy()
    to_encode['uid'] = uid
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire, 'grant_type': grant_type})
    return jwt.encode(to_encode, secret)


async def _get_user_from_token(
    settings: Settings,
    session: AsyncSession,
    token: str,
    mfa_creds: Creds | None,
) -> User:
    """Get user from jwt.

    :param Settings settings: app settings, defaults to Depends(get_settings)
    :param AsyncSession session: sa session, defaults to Depends(get_session)
    :param str token: oauth2 obj, defaults to Depends(oauth2)
    :raises _CREDENTIALS_EXCEPTION: 401
    :return User: user for api response
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=_ALGORITHM)
    except (JWTError, AttributeError):
        if not mfa_creds:
            raise _CREDENTIALS_EXCEPTION

        try:  # retry with mfa secret
            payload = jwt.decode(
                token, mfa_creds.secret, audience=mfa_creds.key)
        except (JWTError, AttributeError):
            raise _CREDENTIALS_EXCEPTION

    user_id: int = int(payload.get("uid"))
    if user_id is None:
        raise _CREDENTIALS_EXCEPTION

    user = await session.get(DBUser, user_id)
    if user is None:
        raise _CREDENTIALS_EXCEPTION

    return User.from_db(user, payload.get("grant_type"), payload.get("exp"))


async def get_current_user(  # noqa: D103
    settings: Annotated[Settings, Depends(get_settings)],
    session: Annotated[AsyncSession, Depends(get_session)],
    token: Annotated[str, Depends(oauth2)],
    mfa_creds: Annotated[str | None, Depends(get_auth)],
) -> User:
    user = await _get_user_from_token(settings, session, token, mfa_creds)

    if user.access_type == 'multifactor' and\
            user.exp < (
                datetime.utcnow().timestamp() - settings.MFA_TOKEN_LEEWAY):
        raise _CREDENTIALS_EXCEPTION

    return user


async def get_current_user_or_none(  # noqa: D103
    settings: Annotated[Settings, Depends(get_settings)],
    session: Annotated[AsyncSession, Depends(get_session)],
    token: Annotated[str, Depends(oauth2)],
    mfa_creds: Annotated[str | None, Depends(get_auth)],
) -> User | None:
    try:
        return await get_current_user(settings, session, token, mfa_creds)
    except Exception:
        return None


async def get_current_user_refresh(  # noqa: D103
    settings: Annotated[Settings, Depends(get_settings)],
    session: Annotated[AsyncSession, Depends(get_session)],
    token: Annotated[str, Depends(oauth2)],
    mfa_creds: Annotated[str | None, Depends(get_auth)],
) -> User:
    user = await _get_user_from_token(settings, session, token, mfa_creds)
    if user._access_type not in ('refresh', 'multifactor'):
        raise _CREDENTIALS_EXCEPTION

    return user

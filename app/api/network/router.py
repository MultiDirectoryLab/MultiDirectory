"""Network policies."""

from fastapi.params import Depends
from fastapi.routing import APIRouter
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from api.auth import User, get_current_user
from models.database import AsyncSession, get_session
from models.ldap3 import NetworkPolicy

from .schema import Policy, PolicyResponse, PolicyUpdate

network_router = APIRouter()


@network_router.post('/policy')
async def add_network_policy(
    policy: Policy,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> bool:
    """Add newtwork."""
    try:
        session.add(NetworkPolicy(name=policy.name, netmasks=policy.netmasks))
        await session.commit()
    except IntegrityError:
        return False
    return True


@network_router.get('/policy')
async def get_network_policies(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[PolicyResponse]:
    """Get network."""
    return [
        PolicyResponse.from_orm(policy)
        for policy in await session.scalars(select(NetworkPolicy))]


@network_router.delete('/policy')
async def delete_network_policy(
    policy_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> bool:
    """Delete network."""
    await session.execute(delete(NetworkPolicy).filter_by(id=policy_id))
    return True


@network_router.put('/policy')
async def switch_network_policy(
    policy: PolicyUpdate,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> bool:
    """Set state of network."""
    await session.execute(
        update(NetworkPolicy)
        .values(enabled=policy.is_enabled)
        .filter_by(id=policy.id))
    return True

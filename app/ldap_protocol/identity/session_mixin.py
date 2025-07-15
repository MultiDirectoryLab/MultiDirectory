"""Mixin for session key creation and management.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from config import Settings
from ldap_protocol.session_storage import SessionStorage
from models import User


class SessionKeyCreatorMixin:
    """Provides a method to create a session key for a user."""

    async def create_session_key(
        self,
        user: User,
        storage: SessionStorage,
        settings: Settings,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> str:
        """Create a session key for the user.

        :param User user: db user
        :param SessionStorage storage: session storage
        :param Settings settings: app settings
        :param ip: client IP
        :param user_agent: client user agent
        :return: session key (str)
        """
        return await storage.create_session(
            user.id,
            settings,
            extra_data={
                "ip": str(ip),
                "user_agent": storage.get_user_agent_hash(user_agent),
            },
        )

"""OAuth modules.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import inject

from api.auth.adapters import IdentityFastAPIAdapter
from ldap_protocol.dialogue import UserSchema


@inject
async def get_current_user(
    identity_adapter: FromDishka[IdentityFastAPIAdapter],
) -> UserSchema:
    """Retrieve the currently authenticated user and rekey their session.

    This function fetches the current user based on the request's
    authentication credentials and rekeys the user's session
    for security purposes.

    Args:
        identity_adapter (FromDishka[IdentityFastAPIAdapter]): The user adapter
            instance injected from Dishka DI container, used for
            user operations.

    Returns:
        UserSchema: The schema representation of the currently
            authenticated user.

    """
    return await identity_adapter.get_current_user()

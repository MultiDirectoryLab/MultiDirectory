"""OAuth modules.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Response

from api.auth.adapters.current_user_gateway import CurrentUserGateway
from ldap_protocol.dialogue import UserSchema


@inject
async def get_current_user(
    current_user_gateway: FromDishka[CurrentUserGateway],
    response: Response,
) -> UserSchema:
    """Retrieve the currently authenticated user and rekey their session.

    This function fetches the current user based on the request's
    authentication credentials and rekeys the user's session
    for security purposes.

    Args:
        current_user_gateway (FromDishka[CurrentUserGateway]): The user adapter
            instance injected from Dishka DI container, used for
            user operations.
        response (Response): The HTTP response object used to set
            session cookies.

    Returns:
        UserSchema: The schema representation of the currently
            authenticated user.

    """
    user = await current_user_gateway.get_current_user()
    await current_user_gateway.rekey_session(response)

    return user

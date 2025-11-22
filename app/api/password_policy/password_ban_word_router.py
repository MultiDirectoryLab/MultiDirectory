"""Password Ban Word router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from fastapi import Depends, UploadFile, status
from fastapi.responses import StreamingResponse
from fastapi_error_map.routing import ErrorAwareRouter
from password_policy import error_map

from api.auth import verify_auth
from api.password_policy.adapter import PasswordBanWordsFastAPIAdapter
from errors import DishkaErrorAwareRoute

password_ban_word_router = ErrorAwareRouter(
    prefix="/password_ban_word",
    tags=["Password Ban Word"],
    dependencies=[Depends(verify_auth)],
    route_class=DishkaErrorAwareRoute,
)


@password_ban_word_router.post(
    "/upload_txt",
    status_code=status.HTTP_201_CREATED,
    error_map=error_map,
)
async def upload_ban_words_txt(
    file: UploadFile,
    password_ban_word_adapter: FromDishka[PasswordBanWordsFastAPIAdapter],
) -> None:
    """Upload .txt file with ban words (one per line) and create them in batch.

    \f
    Args:
        file (UploadFile): Uploaded .txt file.
        password_ban_word_adapter (FromDishka[PasswordBanWordsAdapter]):
        Ban Words adapter.
    """
    await password_ban_word_adapter.upload_ban_words_txt(file)


@password_ban_word_router.get(
    "/download_txt",
    response_class=StreamingResponse,
    status_code=status.HTTP_200_OK,
    error_map=error_map,
)
async def download_ban_words_txt(
    password_ban_word_adapter: FromDishka[PasswordBanWordsFastAPIAdapter],
) -> StreamingResponse:
    """Download all ban words as a .txt file, each word on a new line."""
    return await password_ban_word_adapter.download_ban_words_txt()

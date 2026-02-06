"""Utils with master database check.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import HTTPException, status

from application.master_check_use_case import MasterCheckUseCase


@inject
async def require_master_db(
    master_check_use_case: FromDishka[MasterCheckUseCase],
) -> None:
    if not await master_check_use_case.check_master():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Master DB is not available",
        )

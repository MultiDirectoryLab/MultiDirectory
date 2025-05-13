"""Main MiltiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import uvloop
from alembic.config import Config


async def aboba() -> None:
    """Aboba function."""
    from loguru import logger

    logger.info(uvloop)
    logger.info(Config)

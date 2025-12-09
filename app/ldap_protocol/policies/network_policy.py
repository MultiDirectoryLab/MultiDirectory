"""Network policy manager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Group, NetworkPolicy, User
from repo.pg.tables import queryable_attr as qa

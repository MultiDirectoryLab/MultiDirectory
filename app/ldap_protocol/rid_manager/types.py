"""RID manager typed DI tokens.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import NewType

import redis.asyncio as redis

HostMachineShortName = NewType("HostMachineShortName", str)
ObjectSidCacheRedisClient = NewType("ObjectSidCacheRedisClient", redis.Redis)

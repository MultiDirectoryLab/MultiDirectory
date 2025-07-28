import time
from datetime import datetime

from models import Attribute, Directory


async def add_lock_and_expire_attributes(session, directory: Directory, tz):
    """Add `nsAccountLock` and `shadowExpire` attributes to the directory."""
    now_with_tz = datetime.now(tz=tz)
    absolute_date = int(time.mktime(now_with_tz.timetuple()) / 86400)
    session.add_all(
        [
            Attribute(
                name="nsAccountLock",
                value="true",
                directory=directory,
            ),
            Attribute(
                name="shadowExpire",
                value=str(absolute_date),
                directory=directory,
            ),
        ]
    )
    await session.flush()

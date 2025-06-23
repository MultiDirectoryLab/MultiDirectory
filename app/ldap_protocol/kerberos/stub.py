"""Stub calls for kadmin client."""

from typing import NoReturn

from .base import AbstractKadmin, KRBAPIError
from .utils import logger_wraps


class StubKadminMDADPIClient(AbstractKadmin):
    """Stub client for non set up dirs."""

    @logger_wraps()
    async def setup(self, *args, **kwargs) -> None:  # type: ignore
        """Call setup."""
        await super().setup(*args, **kwargs)

    @logger_wraps(is_stub=True)
    async def add_principal(  # noqa: D102
        self,
        name: str,
        password: str | None,
        timeout: int = 1,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_principal(self, name: str) -> None: ...  # noqa: D102

    @logger_wraps(is_stub=True)
    async def del_principal(self, name: str) -> None: ...  # noqa: D102

    @logger_wraps(is_stub=True)
    async def change_principal_password(  # noqa: D102
        self,
        name: str,
        password: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def create_or_update_principal_pw(  # noqa: D102
        self,
        name: str,
        password: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def rename_princ(self, name: str, new_name: str) -> None: ...  # noqa: D102

    @logger_wraps(is_stub=True)
    async def ktadd(self, names: list[str]) -> NoReturn:  # noqa: ARG002 D102
        raise KRBAPIError

    @logger_wraps(is_stub=True)
    async def lock_principal(self, name: str) -> None: ...  # noqa: D102

    @logger_wraps(is_stub=True)
    async def force_princ_pw_change(self, name: str) -> None: ...  # noqa: D102

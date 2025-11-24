"""Password Policy adapter for FastAPI.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import io

from adaptix.conversion import get_converter
from fastapi import UploadFile, status
from fastapi.responses import StreamingResponse

from api.base_adapter import BaseAdapter
from api.password_policy.schemas import PasswordPolicySchema, PriorityT
from ldap_protocol.policies.password.dataclasses import PasswordPolicyDTO
from ldap_protocol.policies.password.exceptions import (
    PasswordBanWordFileHasDuplicatesError,
    PasswordBanWordWrongFileExtensionError,
    PasswordPolicyAgeDaysError,
    PasswordPolicyAlreadyExistsError,
    PasswordPolicyBaseDnNotFoundError,
    PasswordPolicyCantChangeDefaultDomainError,
    PasswordPolicyDirIsNotUserError,
    PasswordPolicyNotFoundError,
    PasswordPolicyPriorityError,
)
from ldap_protocol.policies.password.use_cases import (
    PasswordBanWordUseCases,
    PasswordPolicyUseCases,
)

_convert_schema_to_dto = get_converter(PasswordPolicySchema, PasswordPolicyDTO)
_convert_dto_to_schema = get_converter(
    PasswordPolicyDTO[int, int],
    PasswordPolicySchema[int],
)


class PasswordPolicyFastAPIAdapter(BaseAdapter[PasswordPolicyUseCases]):
    """Adapter for password policies."""

    _exceptions_map: dict[type[Exception], int] = {
        PasswordPolicyBaseDnNotFoundError: status.HTTP_404_NOT_FOUND,
        PasswordPolicyNotFoundError: status.HTTP_404_NOT_FOUND,
        PasswordPolicyDirIsNotUserError: status.HTTP_404_NOT_FOUND,
        PasswordPolicyAlreadyExistsError: status.HTTP_409_CONFLICT,
        PasswordPolicyCantChangeDefaultDomainError: status.HTTP_400_BAD_REQUEST,  # noqa: E501
        PasswordPolicyPriorityError: status.HTTP_400_BAD_REQUEST,
        PasswordPolicyAgeDaysError: status.HTTP_400_BAD_REQUEST,
    }

    async def get_all(self) -> list[PasswordPolicySchema[int]]:
        """Get all Password Policies."""
        dtos = await self._service.get_all()
        return list(map(_convert_dto_to_schema, dtos))

    async def get(self, id_: int) -> PasswordPolicySchema[int]:
        """Get one Password Policy."""
        dto = await self._service.get(id_)
        return _convert_dto_to_schema(dto)

    async def get_password_policy_by_dir_path_dn(
        self,
        path_dn: str,
    ) -> PasswordPolicySchema[int]:
        """Get one Password Policy for one Directory by its path."""
        dto = await self._service.get_password_policy_by_dir_path_dn(
            path_dn,
        )
        return _convert_dto_to_schema(dto)

    async def update(
        self,
        id_: int,
        policy: PasswordPolicySchema[PriorityT],
    ) -> None:
        """Update one Password Policy."""
        dto = _convert_schema_to_dto(policy)
        await self._service.update(id_, dto)

    async def reset_domain_policy_to_default_config(self) -> None:
        """Reset domain Password Policy to default configuration."""
        await self._service.reset_domain_policy_to_default_config()


class PasswordBanWordsFastAPIAdapter(BaseAdapter[PasswordBanWordUseCases]):
    """Adapter for password ban words."""

    _exceptions_map: dict[type[Exception], int] = {
        PasswordBanWordWrongFileExtensionError: status.HTTP_400_BAD_REQUEST,
        PasswordBanWordFileHasDuplicatesError: status.HTTP_409_CONFLICT,
    }

    async def upload_ban_words_txt(self, file: UploadFile) -> None:
        if (
            file
            and file.filename
            and not file.filename.lower().endswith(".txt")
        ):
            raise PasswordBanWordWrongFileExtensionError(
                "Only '.txt' files are allowed",
            )

        content = await file.read()
        lines = content.decode("utf-8").splitlines()
        ban_words = self._service.filter_ban_words(lines)
        await self._service.replace_all_ban_words(ban_words)

    async def download_ban_words_txt(self) -> StreamingResponse:
        """Download all ban words as a .txt file, each word on a new line.

        \f
        Args:
            password_ban_word_adapter (FromDishka[PasswordBanWordsAdapter]):
            Ban Words adapter.

        Returns:
            StreamingResponse: Streaming response containing the .txt file with
            ban words.

        """
        ban_words = await self._service.get_all()
        file_content = "\n".join(ban_words)

        file_like = io.BytesIO(file_content.encode("utf-8"))
        return StreamingResponse(
            file_like,
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=ban_words.txt",
            },
        )

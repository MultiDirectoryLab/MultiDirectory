"""Delete Directory UseCase."""

from application.access_use_case import AccessControlUseCase
from application.deletion_validator import DirectoryDeletionValidator
from domain.directory.deletion_exception import DirectoryNotFoundError
from domain.directory.gateway_protocol import DirectoryGatewayProtocol

from entities import Directory
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.kerberos.base import AbstractKadmin
from ldap_protocol.session_storage.base import SessionStorage


class DeleteDirectoryUseCase:

    def __init__(
        self,
        directory_gateway: DirectoryGatewayProtocol,  # интерфейс
        directory_deletion_validator: DirectoryDeletionValidator,  # реализация
        access_control_use_case: AccessControlUseCase,  # реализация
        session_storage: SessionStorage,  # интерфейс
        kadmin: AbstractKadmin,  # интерфейс
    ) -> None:
        self._directory_gateway = directory_gateway
        self._directory_deletion_validator = directory_deletion_validator
        self._access_control_use_case = access_control_use_case
        self._session_storage = session_storage
        self._kadmin = kadmin

    async def execute(self, dn: str, user: UserSchema) -> None:
        directory = await self._directory_gateway.get_by_dn(dn)
        if not directory:
            raise DirectoryNotFoundError()

        await self._directory_deletion_validator.validate(directory, user)

        if not await self._access_control_use_case.can_delete(directory, user):
            raise PermissionError()

        if directory.is_user:
            await self._prepare_user_deletion(directory)

        if directory.is_computer:
            await self._prepare_computer_deletion(directory)

        await self._directory_gateway.delete(directory)
        await self._directory_gateway.commit()

    async def _prepare_user_deletion(self, directory: Directory) -> None:
        await self._session_storage.clear_user_sessions(directory.user.id)
        await self._kadmin.del_principal(directory.user.sam_account_name)

    async def _prepare_computer_deletion(self, directory: Directory) -> None:
        for principal_name in directory.computer_principal_names:
            await self._kadmin.del_principal(principal_name)


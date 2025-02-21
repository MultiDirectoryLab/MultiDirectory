"""LDAP protocol map.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .abandon import AbandonRequest
from .add import AddRequest
from .base import BaseRequest
from .bind import BindRequest, UnbindRequest
from .delete import DeleteRequest
from .extended import ExtendedRequest
from .modify import ModifyRequest
from .modify_dn import ModifyDNRequest
from .search import SearchRequest

requests: list[type[BaseRequest]] = [
    AbandonRequest,
    AddRequest,
    BindRequest,
    UnbindRequest,
    DeleteRequest,
    ExtendedRequest,
    ModifyRequest,
    ModifyDNRequest,
    SearchRequest,
]

protocol_id_map: dict[int, type[BaseRequest]] = {
    request.PROTOCOL_OP: request  # type: ignore
    for request in requests
}


__all__ = ["protocol_id_map", "BaseRequest"]

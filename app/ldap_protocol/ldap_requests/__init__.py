"""LDAP protocol map."""

from .abandon import AbandonRequest
from .add import AddRequest
from .base import BaseRequest
from .bind import BindRequest, UnbindRequest
from .compare import CompareRequest
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
    CompareRequest,
    DeleteRequest,
    ExtendedRequest,
    ModifyRequest,
    ModifyDNRequest,
    SearchRequest,
]

protocol_id_map = {request.PROTOCOL_OP: request for request in requests}


__all__ = ['protocol_id_map', 'BaseRequest']

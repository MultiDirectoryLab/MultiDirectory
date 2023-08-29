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

protocol_id_map: dict[int, type[BaseRequest]] = \
    {request.PROTOCOL_OP: request  # type: ignore
        for request in BaseRequest.__subclasses__()}


__all__ = [
    'protocol_id_map',
    'AbandonRequest',
    'AddRequest',
    'BindRequest',
    'UnbindRequest',
    'CompareRequest',
    'DeleteRequest',
    'ExtendedRequest',
    'ModifyRequest',
    'ModifyDNRequest',
    'SearchRequest',
]

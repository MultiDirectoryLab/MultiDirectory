"""LDAP requests structure bind."""

from abc import ABC, abstractmethod

from pydantic import BaseModel

from .asn1parser import ASN1Row


class BaseRequest(ABC, BaseModel):
    """Base request builder."""

    @abstractmethod
    @classmethod
    def from_data_list(cls, data: list[ASN1Row]) -> 'BaseRequest':
        """Create structure from ASN1Row dataclass list."""


class BindRequest(BaseRequest):
    pass


class UnbindRequest(BaseRequest):
    pass


class SearchRequest(BaseRequest):
    pass


class ModifyRequest(BaseRequest):
    pass


class AddRequest(BaseRequest):
    pass


class DeleteRequest(BaseRequest):
    pass


class ModifyDNRequest(BaseRequest):
    pass


class CompareRequest(BaseRequest):
    pass


class AbandonRequest(BaseRequest):
    pass


class ExtendedRequest(BaseRequest):
    pass


# TODO: add support for all codes
message_id_map: dict[int, type[BaseRequest]] = {
    0: BindRequest,
    1: 'Bind Response',
    2: UnbindRequest,
    3: SearchRequest,
    4: 'search Result Entry',
    5: 'search Result Done',
    6: ModifyRequest,
    7: 'Modify Response',
    8: AddRequest,
    9: 'Add Response',
    10: DeleteRequest,
    11: 'Delete Response',
    12: ModifyDNRequest,
    13: 'Modify DN Response',
    14: CompareRequest,
    15: 'compare Response',
    16: AbandonRequest,
    17: 'reserved',
    18: 'reserved',
    19: 'Search Result Reference',
    20: 'reserved',
    21: 'reserved',
    22: 'reserved',
    23: ExtendedRequest,
    24: 'Extended Response',
    25: 'intermediate Response',
}
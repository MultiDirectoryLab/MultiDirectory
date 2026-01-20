"""Module for dtos."""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from adaptix.conversion import get_converter

from entities import Directory, DistinguishedNamePrefix


@dataclass
class DirectoryDTO:
    id: int
    name: str
    is_system: bool
    object_sid: str
    object_guid: uuid.UUID
    parent_id: int | None
    entity_type_id: int | None
    object_class: str
    rdname: str
    created_at: datetime | None
    updated_at: datetime | None
    depth: int
    password_policy_id: int | None
    path: list[str]

    search_fields: ClassVar[dict[str, str]] = {
        "name": "name",
        "objectguid": "objectGUID",
        "objectsid": "objectSid",
    }
    ro_fields: ClassVar[set[str]] = {
        "uid",
        "whencreated",
        "lastlogon",
        "authtimestamp",
        "objectguid",
        "objectsid",
        "entitytypename",
    }

    def get_dn_prefix(self) -> DistinguishedNamePrefix:
        return {
            "organizationalUnit": "ou",
            "domain": "dc",
            "container": "cn",
        }.get(
            self.object_class,
            "cn",
        )  # type: ignore

    def get_dn(self, dn: str = "cn") -> str:
        return f"{dn}={self.name}"

    @property
    def is_domain(self) -> bool:
        return not self.parent_id and self.object_class == "domain"

    @property
    def host_principal(self) -> str:
        return f"host/{self.name}"

    @property
    def path_dn(self) -> str:
        return ",".join(reversed(self.path))

    def create_path(
        self,
        parent: Directory | None = None,
        dn: str = "cn",
    ) -> None:
        pre = parent.path if parent else []
        self.path = pre + [self.get_dn(dn)]
        self.depth = len(self.path)
        self.rdname = dn

    @property
    def relative_id(self) -> str:
        """Get RID from objectSid.

        Relative Identifier (RID) is the last sub-authority value of a SID.
        """
        if "-" in self.object_sid:
            return self.object_sid.split("-")[-1]
        return ""


_directory_sqla_obj_to_dto = get_converter(Directory, DirectoryDTO)

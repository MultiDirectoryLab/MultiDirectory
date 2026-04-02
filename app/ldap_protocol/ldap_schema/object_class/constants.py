"""Constants for object class property names."""

from enum import StrEnum


class ObjectClassAttributeNames(StrEnum):
    """Attribute Type attribute names."""

    OID = "governsID"
    NAME = "name"
    OBJECT_CLASS = "objectClass"
    SUPERIOR_NAME = "subClassOf"
    KIND = "objectClassCategory"
    ATTRIBUTE_TYPES_MUST = "mustContain"
    ATTRIBUTE_TYPES_MAY = "mayContain"

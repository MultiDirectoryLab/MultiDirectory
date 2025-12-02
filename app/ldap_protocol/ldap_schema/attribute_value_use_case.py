"""Use Case TODO."""

from entities import Directory, User
from ldap_protocol.ldap_schema.attribute_value_validator import (
    AttributeValueValidator,
)


class AttributeValueUseCase:
    """Use Case TODO."""

    __attribute_value_validator: AttributeValueValidator

    def __init__(
        self,
        attribute_value_validator: AttributeValueValidator,
    ) -> None:
        """Initialize Use Case TODO."""
        self.__attribute_value_validator = attribute_value_validator

    def validate_directory_attributes(self, directory: Directory) -> bool: ...
    def validate_user_attributes(self, user: User) -> bool: ...

"""Tests for AttributeValueValidator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest

from ldap_protocol.ldap_schema.attribute_value_validator import (
    AttributeValueValidator,
)


@pytest.fixture
def validator() -> AttributeValueValidator:
    """Create validator instance."""
    return AttributeValueValidator()


class TestOrganizationalUnitName:
    """Tests for Organizational Unit name validation."""

    def test_valid_names(self, validator: AttributeValueValidator) -> None:
        """Test valid organizational unit names."""
        valid_names = [
            "IT Department",
            "Sales",
            "Marketing-Team",
            "HR_Department",
            "Department123",
        ]
        for name in valid_names:
            assert validator.validate_value(
                "Organizational Unit",
                "name",
                name,
            )

    def test_invalid_names_with_space_at_start(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test organizational unit names starting with space."""
        invalid_names = [" IT", " Sales", "  Marketing"]
        for name in invalid_names:
            assert not validator.validate_value(
                "Organizational Unit",
                "name",
                name,
            )

    def test_invalid_names_with_hash_at_start(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test organizational unit names starting with hash."""
        invalid_names = ["#IT", "#Sales", "#Marketing"]
        for name in invalid_names:
            assert not validator.validate_value(
                "Organizational Unit",
                "name",
                name,
            )

    def test_invalid_names_with_space_at_end(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test organizational unit names ending with space."""
        invalid_names = ["IT ", "Sales  ", "Marketing   "]
        for name in invalid_names:
            assert not validator.validate_value(
                "Organizational Unit",
                "name",
                name,
            )

    def test_invalid_names_with_forbidden_symbols(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test organizational unit names with forbidden symbols."""
        invalid_names = [
            'IT"Dept',
            "Sales,Team",
            "Marketing+",
            "HR\\Group",
            "Dept<1>",
            "Team;A",
            "Group=B",
        ]
        for name in invalid_names:
            assert not validator.validate_value(
                "Organizational Unit",
                "name",
                name,
            )


class TestGroupName:
    """Tests for Group name validation."""

    def test_valid_names(self, validator: AttributeValueValidator) -> None:
        """Test valid group names."""
        valid_names = [
            "Administrators",
            "Users",
            "Power_Users",
            "Group-123",
            "TeamA",
        ]
        for name in valid_names:
            assert validator.validate_value(
                "Group",
                "name",
                name,
            )

    def test_invalid_names_with_space_at_start(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test group names starting with space."""
        invalid_names = [" Admins", " Users", "  PowerUsers"]
        for name in invalid_names:
            assert not validator.validate_value(
                "Group",
                "name",
                name,
            )

    def test_invalid_names_with_hash_at_start(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test group names starting with hash."""
        invalid_names = ["#Admins", "#Users", "#PowerUsers"]
        for name in invalid_names:
            assert not validator.validate_value(
                "Group",
                "name",
                name,
            )

    def test_invalid_names_with_space_at_end(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test group names ending with space."""
        invalid_names = ["Admins ", "Users  ", "PowerUsers   "]
        for name in invalid_names:
            assert not validator.validate_value(
                "Group",
                "name",
                name,
            )

    def test_invalid_names_with_forbidden_symbols(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test group names with forbidden symbols."""
        invalid_names = [
            'Admins"Group',
            "Users,Team",
            "Power+Users",
            "Group\\A",
            "Team<1>",
            "Users;B",
            "Group=C",
        ]
        for name in invalid_names:
            assert not validator.validate_value(
                "Group",
                "name",
                name,
            )


class TestUserName:
    """Tests for User name validation."""

    def test_valid_names(self, validator: AttributeValueValidator) -> None:
        """Test valid user names."""
        valid_names = [
            "John Doe",
            "Jane_Smith",
            "User-123",
            "Administrator",
            "User.Name",
        ]
        for name in valid_names:
            assert validator.validate_value(
                "User",
                "name",
                name,
            )

    def test_invalid_names_with_space_at_start(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test user names starting with space."""
        invalid_names = [" JohnDoe", " Jane", "  User123"]
        for name in invalid_names:
            assert not validator.validate_value(
                "User",
                "name",
                name,
            )

    def test_invalid_names_with_hash_at_start(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test user names starting with hash."""
        invalid_names = ["#JohnDoe", "#Jane", "#User123"]
        for name in invalid_names:
            assert not validator.validate_value(
                "User",
                "name",
                name,
            )

    def test_invalid_names_with_space_at_end(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test user names ending with space."""
        invalid_names = ["JohnDoe ", "Jane  ", "User123   "]
        for name in invalid_names:
            assert not validator.validate_value(
                "User",
                "name",
                name,
            )

    def test_invalid_names_with_forbidden_symbols(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test user names with forbidden symbols."""
        invalid_names = [
            'John"Doe',
            "Jane,Smith",
            "User+123",
            "Name\\Test",
            "User<1>",
            "John;Doe",
            "User=Name",
        ]
        for name in invalid_names:
            assert not validator.validate_value(
                "User",
                "name",
                name,
            )


class TestUserSAMAccountName:
    """Tests for User sAMAccountName validation."""

    def test_valid_sam_account_names(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test valid sAMAccountName values."""
        valid_names = [
            "jdoe",
            "john.doe",
            "user123",
            "admin_user",
            "test-user",
        ]
        for name in valid_names:
            assert validator.validate_value(
                "User",
                "sAMAccountName",
                name,
            )

    def test_invalid_sam_account_names_with_forbidden_symbols(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test sAMAccountName with forbidden symbols."""
        invalid_names = [
            'user"name',
            "user/name",
            "user\\name",
            "user[name]",
            "user:name",
            "user;name",
            "user|name",
            "user=name",
            "user,name",
            "user+name",
            "user*name",
            "user?name",
            "user<name>",
        ]
        for name in invalid_names:
            assert not validator.validate_value(
                "User",
                "sAMAccountName",
                name,
            )

    def test_invalid_sam_account_names_ending_with_dot(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test sAMAccountName ending with dot."""
        invalid_names = ["user.", "john.doe.", "admin."]
        for name in invalid_names:
            assert not validator.validate_value(
                "User",
                "sAMAccountName",
                name,
            )

    def test_invalid_sam_account_names_with_control_chars(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test sAMAccountName with control characters."""
        invalid_names = [
            "user\x00name",
            "user\x01name",
            "user\x1fname",
            "user\x7fname",
        ]
        for name in invalid_names:
            assert not validator.validate_value(
                "User",
                "sAMAccountName",
                name,
            )

    def test_invalid_sam_account_names_with_at_symbol(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test sAMAccountName with @ symbol."""
        invalid_names = ["user@domain", "admin@test", "john@"]
        for name in invalid_names:
            assert not validator.validate_value(
                "User",
                "sAMAccountName",
                name,
            )


class TestComputerName:
    """Tests for Computer name validation."""

    def test_valid_names(self, validator: AttributeValueValidator) -> None:
        """Test valid computer names."""
        valid_names = [
            "WORKSTATION01",
            "Server-2024",
            "PC_LAB_123",
            "Desktop",
        ]
        for name in valid_names:
            assert validator.validate_value(
                "Computer",
                "name",
                name,
            )

    def test_invalid_names_with_space_at_start(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test computer names starting with space."""
        invalid_names = [" WORKSTATION", " Server", "  PC123"]
        for name in invalid_names:
            assert not validator.validate_value(
                "Computer",
                "name",
                name,
            )

    def test_invalid_names_with_hash_at_start(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test computer names starting with hash."""
        invalid_names = ["#WORKSTATION", "#Server", "#PC123"]
        for name in invalid_names:
            assert not validator.validate_value(
                "Computer",
                "name",
                name,
            )

    def test_invalid_names_with_space_at_end(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test computer names ending with space."""
        invalid_names = ["WORKSTATION ", "Server  ", "PC123   "]
        for name in invalid_names:
            assert not validator.validate_value(
                "Computer",
                "name",
                name,
            )

    def test_invalid_names_with_forbidden_symbols(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test computer names with forbidden symbols."""
        invalid_names = [
            'PC"01',
            "Server,01",
            "Work+Station",
            "PC\\01",
            "Server<1>",
            "PC;01",
            "Computer=01",
        ]
        for name in invalid_names:
            assert not validator.validate_value(
                "Computer",
                "name",
                name,
            )


class TestComputerSAMAccountName:
    """Tests for Computer sAMAccountName validation."""

    def test_valid_sam_account_names(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test valid computer sAMAccountName values."""
        valid_names = [
            "WORKSTATION01$",
            "SERVER-2024$",
            "PC_LAB$",
        ]
        for name in valid_names:
            assert validator.validate_value(
                "Computer",
                "sAMAccountName",
                name,
            )

    def test_invalid_sam_account_names_with_forbidden_symbols(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test computer sAMAccountName with forbidden symbols."""
        invalid_names = [
            'PC"01$',
            "PC/01$",
            "PC\\01$",
            "PC[01]$",
            "PC:01$",
            "PC;01$",
            "PC|01$",
            "PC=01$",
            "PC,01$",
            "PC+01$",
            "PC*01$",
            "PC?01$",
            "PC<01>$",
        ]
        for name in invalid_names:
            assert not validator.validate_value(
                "Computer",
                "sAMAccountName",
                name,
            )

    def test_invalid_sam_account_names_ending_with_dot(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test computer sAMAccountName ending with dot."""
        invalid_names = ["PC01.", "SERVER.", "WORKSTATION."]
        for name in invalid_names:
            assert not validator.validate_value(
                "Computer",
                "sAMAccountName",
                name,
            )

    def test_invalid_sam_account_names_with_control_chars(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test computer sAMAccountName with control characters."""
        invalid_names = [
            "PC\x00NAME$",
            "PC\x01NAME$",
            "PC\x1fNAME$",
            "PC\x7fNAME$",
        ]
        for name in invalid_names:
            assert not validator.validate_value(
                "Computer",
                "sAMAccountName",
                name,
            )

    def test_invalid_sam_account_names_with_spaces_and_dots(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test computer sAMAccountName with spaces and dots."""
        invalid_names = [
            "PC 01$",
            "SERVER 2024$",
            "WORK.STATION$",
            "PC.01$",
        ]
        for name in invalid_names:
            assert not validator.validate_value(
                "Computer",
                "sAMAccountName",
                name,
            )

    def test_invalid_sam_account_names_only_numbers(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test computer sAMAccountName that are only numbers."""
        invalid_names = ["123", "456789", "0"]
        for name in invalid_names:
            assert not validator.validate_value(
                "Computer",
                "sAMAccountName",
                name,
            )

    def test_invalid_sam_account_names_starting_with_number(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test computer sAMAccountName starting with number."""
        invalid_names = ["1PC$", "2SERVER$", "9WORKSTATION$"]
        for name in invalid_names:
            assert not validator.validate_value(
                "Computer",
                "sAMAccountName",
                name,
            )


class TestNoValidationRules:
    """Test validation for attributes without specific rules."""

    def test_attributes_without_rules_always_valid(
        self,
        validator: AttributeValueValidator,
    ) -> None:
        """Test that attributes without validation rules always pass."""
        test_cases = [
            ("User", "description", "Any value here!"),
            ("Group", "description", " spaces and #symbols "),
            ("Computer", "location", "Building 1, Room 101"),
            ("Organizational Unit", "description", ""),
        ]

        for entity_type, property_name, value in test_cases:
            assert validator.validate_value(
                entity_type,  # type: ignore
                property_name,
                value,
            )

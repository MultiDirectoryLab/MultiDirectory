"""Tests for error handling mechanism.

Tests for ErrorCodeCarrierError, ErrorCatalog, HttpCodeMapper, and BaseAdapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from fastapi import HTTPException, status

from abstract_dao import AbstractService
from api.base_adapter import BaseAdapter
from enums import ErrorCode
from errors.catalog import ErrorCatalog
from errors.contracts import ErrorCodeCarrierError, HasErrorCode
from errors.http_mapper import HttpCodeMapper
from ldap_protocol.kerberos.exceptions import KRBAPIChangePasswordError
from ldap_protocol.ldap_schema.exceptions import AttributeTypeNotFoundError


class TestErrorCodeCarrierError:
    """Test ErrorCodeCarrierError wrapper."""

    def test_wraps_exception_with_code(self) -> None:
        """Test that ErrorCodeCarrierError wraps exception with error code."""
        original = ValueError("Test error")
        carrier = ErrorCodeCarrierError(original, ErrorCode.VALUE_ERROR)

        assert carrier.get_error_code() == ErrorCode.VALUE_ERROR
        assert carrier.cause == original
        assert str(carrier) == "Test error"
        assert repr(carrier) == repr(original)

    @pytest.mark.parametrize(
        ("exception", "error_code", "expected_str"),
        [
            (
                RuntimeError("Original message"),
                ErrorCode.RUNTIME_ERROR,
                "Original message",
            ),
            (KeyError("missing_key"), ErrorCode.KEY_ERROR, "'missing_key'"),
        ],
    )
    def test_str_returns_original_message(
        self,
        exception: Exception,
        error_code: ErrorCode,
        expected_str: str,
    ) -> None:
        """Test that str() returns original exception message."""
        carrier = ErrorCodeCarrierError(exception, error_code)

        assert str(carrier) == expected_str

    @pytest.mark.parametrize(
        ("exception", "error_code"),
        [
            (RuntimeError("Original message"), ErrorCode.RUNTIME_ERROR),
            (KeyError("missing_key"), ErrorCode.KEY_ERROR),
        ],
    )
    def test_repr_returns_original_repr(
        self,
        exception: Exception,
        error_code: ErrorCode,
    ) -> None:
        """Test that repr() returns original exception repr."""
        carrier = ErrorCodeCarrierError(exception, error_code)

        assert repr(carrier) == repr(exception)

    def test_implements_has_error_code(self) -> None:
        """Test that ErrorCodeCarrierError implements HasErrorCode protocol."""
        original = Exception("Test")
        carrier = ErrorCodeCarrierError(original, ErrorCode.EXCEPTION)

        assert isinstance(carrier, HasErrorCode)
        assert hasattr(carrier, "get_error_code")
        assert carrier.get_error_code() == ErrorCode.EXCEPTION


class TestErrorCatalog:
    """Test ErrorCatalog exception resolution."""

    def test_resolves_known_exception(self) -> None:
        """Test that catalog resolves known exception to ErrorCode."""
        catalog = ErrorCatalog()
        exc = ValueError("Test")

        code = catalog.resolve(exc)

        assert code == ErrorCode.VALUE_ERROR

    def test_resolves_exception_class(self) -> None:
        """Test that catalog resolves exception class (not instance)."""
        catalog = ErrorCatalog()

        code = catalog.resolve(ValueError)

        assert code == ErrorCode.VALUE_ERROR

    def test_returns_none_for_unknown_exception(self) -> None:
        """Test that catalog returns None for unknown exception."""
        catalog = ErrorCatalog()

        class UnknownError(Exception):
            pass

        code = catalog.resolve(UnknownError())

        assert code is None

    @pytest.mark.parametrize(
        ("exception", "expected_code"),
        [
            (
                KRBAPIChangePasswordError("Test"),
                ErrorCode.KERBEROS_CHANGE_PASSWORD_ERROR,
            ),
            (
                AttributeTypeNotFoundError("Test"),
                ErrorCode.ATTRIBUTE_TYPE_NOT_FOUND,
            ),
        ],
    )
    def test_resolves_specific_exceptions(
        self,
        exception: Exception,
        expected_code: ErrorCode,
    ) -> None:
        """Test that catalog resolves specific exceptions to ErrorCode."""
        catalog = ErrorCatalog()

        code = catalog.resolve(exception)

        assert code == expected_code


class TestHttpCodeMapper:
    """Test HttpCodeMapper error code to HTTP status mapping."""

    @pytest.mark.parametrize(
        ("http_code", "expected"),
        [
            (200, 200),
            (400, 400),
            (401, 401),
            (422, 422),
            (500, 500),
            (404, 400),
            (409, 400),
            (403, 401),
            (424, 401),
            (426, 401),
            (503, 500),
            (999, 500),
        ],
    )
    def test_normalize_http(
        self,
        http_code: int,
        expected: int,
    ) -> None:
        """Test that mapper normalizes HTTP codes correctly."""
        mapper = HttpCodeMapper()

        assert mapper.normalize_http(http_code) == expected

    @pytest.mark.parametrize(
        ("error_code", "expected_http"),
        [
            (ErrorCode.AUDIT_ALREADY_EXISTS, 400),
            (ErrorCode.AUTHENTICATION_ERROR, 401),
            (ErrorCode.INTEGRITY_ERROR, 500),
            (ErrorCode.VALIDATION_ERROR, 422),
            (ErrorCode.KERBEROS_CONFLICT, 400),
            (ErrorCode.PERMISSION_ERROR, 401),
            (ErrorCode.KERBEROS_UNAVAILABLE, 500),
        ],
    )
    def test_to_http_maps_error_code_to_normalized_http(
        self,
        error_code: ErrorCode,
        expected_http: int,
    ) -> None:
        """Test that to_http maps ErrorCode to normalized HTTP status."""
        mapper = HttpCodeMapper()

        assert mapper.to_http(error_code) == expected_http


class TestBaseAdapterReraise:
    """Test BaseAdapter._reraise exception handling logic."""

    def test_prioritizes_has_error_code(self) -> None:
        """Test that HasErrorCode exceptions are handled first."""
        from abstract_dao import AbstractService
        from api.base_adapter import BaseAdapter

        class TestService(AbstractService):
            pass

        class TestAdapter(BaseAdapter[TestService]):
            _exceptions_map: dict[type[Exception], int] = {
                ValueError: status.HTTP_400_BAD_REQUEST,
            }

            def __init__(self, service: TestService) -> None:
                super().__init__(service)

        adapter = TestAdapter(TestService())
        carrier = ErrorCodeCarrierError(
            ValueError("Test"),
            ErrorCode.VALUE_ERROR,
        )

        with pytest.raises(HTTPException) as exc_info:
            adapter._reraise(carrier)  # noqa: SLF001

        assert exc_info.value.status_code == 400
        assert str(exc_info.value.detail) == "Test"

    def test_falls_back_to_catalog(self) -> None:
        """Test that ErrorCatalog is checked if not HasErrorCode."""

        class TestService(AbstractService):
            pass

        class TestAdapter(BaseAdapter[TestService]):
            _exceptions_map: dict[type[Exception], int] = {
                ValueError: status.HTTP_400_BAD_REQUEST,
            }

            def __init__(self, service: TestService) -> None:
                super().__init__(service)

        adapter = TestAdapter(TestService())
        exc = ValueError("Test")

        with pytest.raises(HTTPException) as exc_info:
            adapter._reraise(exc)  # noqa: SLF001

        assert exc_info.value.status_code == 400
        assert str(exc_info.value.detail) == "Test"

    def test_falls_back_to_exceptions_map(self) -> None:
        """Test that _exceptions_map is used if catalog doesn't resolve."""
        from abstract_dao import AbstractService
        from api.base_adapter import BaseAdapter

        class TestService(AbstractService):
            pass

        class UnknownError(Exception):
            pass

        class TestAdapter(BaseAdapter[TestService]):
            _exceptions_map: dict[type[Exception], int] = {
                UnknownError: status.HTTP_500_INTERNAL_SERVER_ERROR,
            }

            def __init__(self, service: TestService) -> None:
                super().__init__(service)

        adapter = TestAdapter(TestService())
        exc = UnknownError("Unknown")

        with pytest.raises(HTTPException) as exc_info:
            adapter._reraise(exc)  # noqa: SLF001

        assert exc_info.value.status_code == 500
        assert str(exc_info.value.detail) == "Unknown"

    def test_reraises_if_no_mapping(self) -> None:
        """Test that exception is re-raised if no mapping found."""
        from abstract_dao import AbstractService
        from api.base_adapter import BaseAdapter

        class TestService(AbstractService):
            pass

        class UnmappedError(Exception):
            pass

        class TestAdapter(BaseAdapter[TestService]):
            _exceptions_map: dict[type[Exception], int] = {}

            def __init__(self, service: TestService) -> None:
                super().__init__(service)

        adapter = TestAdapter(TestService())
        exc = UnmappedError("Unmapped")

        with pytest.raises(UnmappedError):
            adapter._reraise(exc)  # noqa: SLF001

    def test_handles_error_code_carrier_with_original_message(self) -> None:
        """Test that ErrorCodeCarrierError uses original exception message."""

        class TestService(AbstractService):
            pass

        class TestAdapter(BaseAdapter[TestService]):
            _exceptions_map: dict[type[Exception], int] = {}

            def __init__(self, service: TestService) -> None:
                super().__init__(service)

        adapter = TestAdapter(TestService())
        original = ValueError("Original message")
        carrier = ErrorCodeCarrierError(original, ErrorCode.VALUE_ERROR)

        with pytest.raises(HTTPException) as exc_info:
            adapter._reraise(carrier)  # noqa: SLF001

        assert str(exc_info.value.detail) == "Original message"
        assert exc_info.value.status_code == 400

    def test_normalizes_http_codes(self) -> None:
        """Test that HTTP codes are normalized through mapper."""

        class TestService(AbstractService):
            pass

        class TestAdapter(BaseAdapter[TestService]):
            _exceptions_map: dict[type[Exception], int] = {}

            def __init__(self, service: TestService) -> None:
                super().__init__(service)

        adapter = TestAdapter(TestService())
        carrier = ErrorCodeCarrierError(
            Exception("Test"),
            ErrorCode.KERBEROS_CONFLICT,
        )

        with pytest.raises(HTTPException) as exc_info:
            adapter._reraise(carrier)  # noqa: SLF001

        assert exc_info.value.status_code == 400

    def test_handles_kerberos_change_password_error(self) -> None:
        """Test that KRBAPIChangePasswordError is handled correctly."""

        class TestService(AbstractService):
            pass

        class TestAdapter(BaseAdapter[TestService]):
            _exceptions_map: dict[type[Exception], int] = {
                KRBAPIChangePasswordError: status.HTTP_424_FAILED_DEPENDENCY,
            }

            def __init__(self, service: TestService) -> None:
                super().__init__(service)

        adapter = TestAdapter(TestService())
        exc = KRBAPIChangePasswordError("Password change failed")

        with pytest.raises(HTTPException) as exc_info:
            adapter._reraise(exc)  # noqa: SLF001

        assert exc_info.value.status_code == 500
        assert str(exc_info.value.detail) == "Password change failed"

    def test_priority_order_has_error_code_over_catalog(self) -> None:
        """Test that HasErrorCode takes priority over ErrorCatalog."""

        class TestService(AbstractService):
            pass

        class TestAdapter(BaseAdapter[TestService]):
            _exceptions_map: dict[type[Exception], int] = {}

            def __init__(self, service: TestService) -> None:
                super().__init__(service)

        adapter = TestAdapter(TestService())
        original = ValueError("Test")
        carrier = ErrorCodeCarrierError(original, ErrorCode.INTEGRITY_ERROR)

        with pytest.raises(HTTPException) as exc_info:
            adapter._reraise(carrier)  # noqa: SLF001

        assert exc_info.value.status_code == 500

    def test_priority_order_catalog_over_exceptions_map(self) -> None:
        """Test that ErrorCatalog takes priority over _exceptions_map."""

        class TestService(AbstractService):
            pass

        class TestAdapter(BaseAdapter[TestService]):
            _exceptions_map: dict[type[Exception], int] = {
                ValueError: status.HTTP_500_INTERNAL_SERVER_ERROR,
            }

            def __init__(self, service: TestService) -> None:
                super().__init__(service)

        adapter = TestAdapter(TestService())
        exc = ValueError("Test")

        with pytest.raises(HTTPException) as exc_info:
            adapter._reraise(exc)  # noqa: SLF001

        assert exc_info.value.status_code == 400

    def test_exception_chaining_preserved(self) -> None:
        """Test that exception chaining is preserved in HTTPException."""

        class TestService(AbstractService):
            pass

        class TestAdapter(BaseAdapter[TestService]):
            _exceptions_map: dict[type[Exception], int] = {}

            def __init__(self, service: TestService) -> None:
                super().__init__(service)

        adapter = TestAdapter(TestService())
        original = ValueError("Original")
        carrier = ErrorCodeCarrierError(original, ErrorCode.VALUE_ERROR)

        with pytest.raises(HTTPException) as exc_info:
            adapter._reraise(carrier)  # noqa: SLF001

        assert exc_info.value.__cause__ == carrier

    def test_all_error_codes_have_valid_http_mapping(self) -> None:
        """Test that all ErrorCode values can be mapped to HTTP status."""
        mapper = HttpCodeMapper()

        for error_code in ErrorCode:
            http_status = mapper.to_http(error_code)
            assert http_status in {200, 400, 401, 422, 500}

    def test_error_code_carrier_preserves_exception_attributes(
        self,
    ) -> None:
        """Test that ErrorCodeCarrierError preserves exception attributes."""
        original = ValueError("Test")
        original.custom_attr = "custom_value"  # type: ignore[attr-defined]

        carrier = ErrorCodeCarrierError(original, ErrorCode.VALUE_ERROR)

        assert carrier.cause.custom_attr == "custom_value"  # type: ignore[attr-defined]

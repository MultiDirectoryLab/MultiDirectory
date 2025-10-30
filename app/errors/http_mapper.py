"""HTTP code mapper for internal ErrorCode values.

Encapsulates policy of translating internal domain error codes to
allowed HTTP status codes.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from __future__ import annotations

from enums import ErrorCode

_ALLOWED = {200, 400, 401, 422, 500}


class HttpCodeMapper:
    """Map ErrorCode to allowed HTTP status codes."""

    @staticmethod
    def _http_from_error_code(code: ErrorCode) -> int:
        """Derive HTTP status from ErrorCode numeric value.

        Convention: NNN NNN NN where first 3 digits are HTTP status.
        """
        return int(code.value) // 100000

    def normalize_http(self, http: int) -> int:
        """Normalize arbitrary HTTP to the allowed policy set."""
        if http in _ALLOWED:
            return http
        if http in {404, 409}:
            return 400
        if http in {403, 424, 426}:
            return 401
        if http == 422:
            return 422
        return 500

    def to_http(self, code: ErrorCode) -> int:
        raw = self._http_from_error_code(code)
        return self.normalize_http(raw)

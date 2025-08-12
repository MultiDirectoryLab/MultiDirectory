"""Error Messages for password validator checks.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class ErrorMessages:
    """Error messages for password validation checks."""

    LONGER = "Password must be longer"

    NOT_OLD_ENOUGH = "Password is not old enough to update"
    NOT_IN_HISTORY = "Password must not be in history"
    NOT_LIKE_OTP = "Password suffix should not be similar to OTP"

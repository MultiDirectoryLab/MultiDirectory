"""LDF file list validator and sorter."""

import re
from pathlib import Path


class LdfFilesValidationError(ValueError):
    """Raised when LDF file list validation fails."""


class LdfFilesValidator:
    """Validate and sort LDF file paths."""

    _name_re = re.compile(r"^sch(?P<num>\d+)(?:\.ldf)?$")

    def execute(self, paths: list[str]) -> list[str]:
        """Validate names and return sorted list of paths.

        :param list[str] paths: input list of file paths
        :return list[str]: sorted list of paths
        """
        if not paths:
            raise LdfFilesValidationError("LDF file list is empty")

        parsed: list[tuple[int, str]] = []
        for path in paths:
            name = Path(path).name
            match = self._name_re.match(name)
            if not match:
                raise LdfFilesValidationError(
                    f"Invalid LDF file name: {name}",
                )
            parsed.append((int(match.group("num")), path))

        parsed.sort(key=lambda item: item[0])
        numbers = [item[0] for item in parsed]

        if numbers[0] != 14:
            raise LdfFilesValidationError(
                "LDF version list must start with sch14",
            )

        for index in range(len(numbers) - 1):
            if numbers[index + 1] != numbers[index] + 1:
                raise LdfFilesValidationError(
                    "LDF version sequence has gaps",
                )

        return [item[1] for item in parsed]

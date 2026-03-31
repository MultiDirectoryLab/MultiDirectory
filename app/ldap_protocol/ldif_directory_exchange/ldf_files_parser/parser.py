"""Parser for LDF files."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from ldap_protocol.ldif_directory_exchange.ldf_files_parser.constants import (
    LdfAttributeOperations,
    LdfEntryChangeTypes,
)
from ldap_protocol.ldif_directory_exchange.ldf_files_parser.dto import (
    LdfAttribute,
    LdfEntry,
    LdfFileDTO,
)


class _LdfFileEntryAttrNames(StrEnum):
    """LDF file operation."""

    DN = "dn"
    CHANGE_TYPE = "changetype"


class LdfFileParser:
    """Parse LDF files into DTOs."""

    _comment_prefix = "#"
    _chunk_start_prefix = "dn:"
    _continuation_line_prefix = " "
    _ignore_line_prefix = "-"

    _base64_value_line_separator = "::"
    _utf8_value_line_separator = ":"

    def execute(self, ldf_file_path: Path) -> LdfFileDTO:
        """Parse LDF file into a structured DTO."""
        lines = ldf_file_path.read_text(encoding="utf-8").splitlines()

        chunks_of_lines = self._parse_lines(lines)

        entries: list[LdfEntry] = []
        for chunk in chunks_of_lines:
            entry = self._parse_chunk(chunk)
            entries.append(entry)

        return LdfFileDTO(
            ldf_file_name=ldf_file_path.name,
            ldf_file_path=str(ldf_file_path),
            entries=entries,
        )

    def _parse_lines(self, lines: list[str]) -> list[list[str]]:
        """Parse lines.

        Input example:
        ```
        [
            # comment line
            dn: CN=First,DC=example,DC=com
            changetype: add
            attr_name1: attr_value1
            attr_name2: attr_value2
            description: Description
             with_continuation_line
            -

            dn: CN=Example-Entry,CN=Schema,CN=Configuration,DC=X
            changetype: ntdsSchemaDelete
        ]
        ```

        Output example:
        ```
        [
            [
                "dn: CN=First,DC=example,DC=com",
                "changetype: add",
                "attr_name1: attr_value1",
                "attr_name2: attr_value2",
                "description: Descriptionwith_continuation_line",
                "-",
            ],
            [
                "dn: CN=Example-Entry,CN=Schema,CN=Configuration,DC=X",
                "changetype: ntdsSchemaDelete",
            ],
        ]
        ```
        """
        chunks: list[list[str]] = []
        current_chunk: list[str] = []

        for line in lines:
            if not line or line.startswith(
                (self._comment_prefix, self._ignore_line_prefix),
            ):
                continue

            elif line.startswith(self._chunk_start_prefix):
                if current_chunk:
                    chunks.append(current_chunk)

                current_chunk = [line]
                continue

            elif line.startswith(self._continuation_line_prefix):
                current_chunk[-1] += line.strip()
                continue

            current_chunk.append(line)

        if current_chunk:
            chunks.append(current_chunk)

        return chunks

    def _parse_chunk(self, chunk: list[str]) -> LdfEntry:
        """Perse chunk.

        Input exaple:
        ```
        [
            dn: CN=MSMQ-Custom-Recipient,CN=Schema,CN=Configuration,DC=X,
            changetype: ntdsSchemaModify,
            replace: defaultHidingValue,
            defaultHidingValue: FALSE,
            add: systemMayContain,
            systemMayContain: 1.2.840.113556.1.4.1695,
            delete: systemMustContain,
            systemMustContain: 1.2.840.113556.1.4.1695,
            add: systemPossSuperiors,
            systemPossSuperiors: 1.2.840.113556.1.5.67,
            systemPossSuperiors: 1.2.840.113556.1.3.23,
        ]
        ```

        Output exaple:
        ```
        LdfEntry(
            dn="CN=MSMQ-Custom-Recipient,CN=Schema,CN=Configuration,DC=X",
            change_type="ntdsSchemaModify",
            ldf_attributes=[
                LdfAttribute(
                    op="replace",
                    name="defaultHidingValue",
                    raw_value="FALSE",
                    is_base64=False,
                    decoded_value="FALSE",
                    decoded_bytes=None,
                ),
                LdfAttribute(
                    op="add",
                    name="systemMayContain",
                    raw_value="1.2.840.113556.1.4.1695",
                    is_base64=False,
                    decoded_value="1.2.840.113556.1.4.1695",
                    decoded_bytes=None,
                ),
                LdfAttribute(
                    op="delete",
                    name="systemMustContain",
                    raw_value="1.2.840.113556.1.4.1695",
                    is_base64=False,
                    decoded_value="1.2.840.113556.1.4.1695",
                    decoded_bytes=None,
                ),
                LdfAttribute(
                    op="add",
                    name="systemPossSuperiors",
                    raw_value="1.2.840.113556.1.5.67",
                    is_base64=False,
                    decoded_value="1.2.840.113556.1.5.67",
                    decoded_bytes=None,
                ),
                LdfAttribute(
                    op="add",
                    name="systemPossSuperiors",
                    raw_value="1.2.840.113556.1.3.23",
                    is_base64=False,
                    decoded_value="1.2.840.113556.1.3.23",
                    decoded_bytes=None,
                ),
            ],
        )
        ```
        """
        ldf_entry = LdfEntry(
            dn=None,
            change_type=None,
            ldf_attributes=[],
        )

        operation = None
        attribute_name = None
        for line in chunk:
            name, value, is_base64 = self._extract_data_from_line(line)

            if name == _LdfFileEntryAttrNames.DN:
                ldf_entry.dn = value
            elif name == _LdfFileEntryAttrNames.CHANGE_TYPE:
                ldf_entry.change_type = LdfEntryChangeTypes(value)
            elif name in LdfAttributeOperations:
                operation = LdfAttributeOperations(name)
                attribute_name = value
            else:
                if operation and attribute_name and name == attribute_name:
                    ldf_attribute = LdfAttribute.from_raw(
                        operation=operation,
                        name=attribute_name,
                        raw_value=value,
                        is_base64=is_base64,
                    )
                    ldf_entry.ldf_attributes.append(ldf_attribute)
                else:
                    raise ValueError(f"Invalid attribute line: {line}.")

        return ldf_entry

    def _extract_data_from_line(self, line: str) -> tuple[str, str, bool]:
        if self._base64_value_line_separator in line:
            name, _, value = line.partition(self._base64_value_line_separator)
            is_base64 = True

        elif self._utf8_value_line_separator in line:
            name, _, value = line.partition(self._utf8_value_line_separator)
            is_base64 = False

        else:
            raise ValueError(
                f"Invalid attribute line: {line}. The line does not contain correct attrName-value separator",  # noqa: E501
            )

        name = name.strip()
        value = value.lstrip(" ") if value is not None else ""

        return name, value, is_base64

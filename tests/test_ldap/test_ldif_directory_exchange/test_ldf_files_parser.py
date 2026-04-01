"""Tests for LDF file parser."""

from __future__ import annotations

from pathlib import Path

from ldap_protocol.ldif_directory_exchange.ldf_files_parser import (
    LdfFileParser,
)
from ldap_protocol.ldif_directory_exchange.ldf_files_parser.constants import (
    LdfEntryChangeTypes,
)


def test_execute_parses_entries_and_attributes(tmp_path: Path) -> None:
    """Parse LDF file into chunks and attributes."""
    content = """# comment line
dn: CN=First,DC=example,DC=com
changetype: ntdsSchemaAdd
replace: attr1
attr1: value1

# another comment
dn: CN=Second,DC=example,DC=com
changetype: ntdsSchemaModify
replace: attr2
attr2:: Zg==
-
add: attr3
attr3: first
 ololo
-
"""

    file_path = tmp_path / "sample.ldf"
    file_path.write_text(content, encoding="utf-8")

    parser = LdfFileParser()
    result = parser.execute(file_path)

    assert result.ldf_file_name == "sample.ldf"
    assert len(result.entries) == 2

    first_entry = result.entries[0]
    assert first_entry.dn == "CN=First,DC=example,DC=com"
    assert first_entry.change_type == LdfEntryChangeTypes.NTDS_SCHEMA_ADD_UP
    assert len(first_entry.ldf_attributes) == 1
    assert first_entry.ldf_attributes[0].name == "attr1"
    assert first_entry.ldf_attributes[0].raw_value == "value1"
    assert first_entry.ldf_attributes[0].decoded_value == "value1"

    second_entry = result.entries[1]
    assert second_entry.dn == "CN=Second,DC=example,DC=com"
    assert second_entry.change_type == LdfEntryChangeTypes.NTDS_SCHEMA_MODIFY
    assert len(second_entry.ldf_attributes) == 2

    attr2 = second_entry.ldf_attributes[0]
    assert attr2.name == "attr2"
    assert attr2.raw_value == "Zg=="
    assert attr2.decoded_bytes == b"f"
    assert attr2.decoded_value == "f"

    description = second_entry.ldf_attributes[1]
    assert description.name == "attr3"
    assert description.raw_value == "firstololo"
    assert description.decoded_value == "firstololo"


def test_parse_lines_splits_chunks_from_sch17() -> None:
    lines = [
        "# leading comment",
        "",
        "dn: CN=First,DC=example,DC=com",
        "changetype: add",
        "replace: description",
        "description: First",
        " continues",
        "-",
        "",
        "dn:",
        "changetype: modify",
        "add: schemaUpdateNow",
        "schemaUpdateNow: 1",
        "-",
    ]

    parser = LdfFileParser()
    chunks = parser._parse_lines(lines)  # noqa: SLF001
    assert chunks == [
        [
            "dn: CN=First,DC=example,DC=com",
            "changetype: add",
            "replace: description",
            "description: Firstcontinues",
        ],
        [
            "dn:",
            "changetype: modify",
            "add: schemaUpdateNow",
            "schemaUpdateNow: 1",
        ],
    ]


def test_parse_chunk_reads_modify_entry_from_sch17() -> None:
    parser = LdfFileParser()
    chunk = [
        "dn: CN=MSMQ-Custom-Recipient,CN=Schema,CN=Configuration,DC=X",
        "changetype: ntdsSchemaModify",
        "replace: defaultHidingValue",
        "defaultHidingValue: FALSE",
        "add: systemMayContain",
        "systemMayContain: 1.2.840.113556.1.4.1695",
        "delete: systemMustContain",
        "systemMustContain: 1.2.840.113556.1.4.1695",
        "add: systemPossSuperiors",
        "systemPossSuperiors: 1.2.840.113556.1.5.67",
        "systemPossSuperiors: 1.2.840.113556.1.3.23",
    ]

    entry = parser._parse_chunk(chunk)  # noqa: SLF001

    assert (
        entry.dn == "CN=MSMQ-Custom-Recipient,CN=Schema,CN=Configuration,DC=X"
    )
    assert entry.change_type == "ntdsSchemaModify"
    assert len(entry.ldf_attributes) == 5


def test_extract_data_from_line_handles_base64() -> None:
    parser = LdfFileParser()

    base64_line = "schemaIdGuid:: FqhZfQW7ckqXH1wTMfZ1WQ=="

    name, raw_value, is_base64 = parser._extract_data_from_line(base64_line)  # noqa: SLF001
    assert name == "schemaIdGuid"
    assert raw_value == "FqhZfQW7ckqXH1wTMfZ1WQ=="
    assert is_base64 is True


def test_extract_data_from_line_handles_base64_and_utf8() -> None:
    parser = LdfFileParser()

    utf8_line = "changetype: ntdsSchemaAdd"

    name, raw_value, is_base64 = parser._extract_data_from_line(utf8_line)  # noqa: SLF001
    assert name == "changetype"
    assert raw_value == "ntdsSchemaAdd"
    assert is_base64 is False


def test_execute_parses_all_ldf_files() -> None:
    parser = LdfFileParser()
    for file_path in Path("app/extra/ldifs").glob("*.ldf"):
        parser.execute(file_path)

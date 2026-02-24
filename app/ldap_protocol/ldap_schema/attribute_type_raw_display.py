""""""

from ldap_protocol.ldap_schema.dto import AttributeTypeDTO


class AttributeTypeRawDisplay:
    @staticmethod
    def get_raw_definition(dto: AttributeTypeDTO) -> str:
        if not dto.oid or not dto.name or not dto.syntax:
            raise ValueError(
                f"{dto}: Fields 'oid', 'name', "
                "and 'syntax' are required for LDAP definition.",
            )
        chunks = [
            "(",
            dto.oid,
            f"NAME '{dto.name}'",
            f"SYNTAX '{dto.syntax}'",
        ]
        if dto.single_value:
            chunks.append("SINGLE-VALUE")
        if dto.no_user_modification:
            chunks.append("NO-USER-MODIFICATION")
        chunks.append(")")
        return " ".join(chunks)

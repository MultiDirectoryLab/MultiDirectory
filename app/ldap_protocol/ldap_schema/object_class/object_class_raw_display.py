"""ObjectClassRawDisplay."""

from ldap_protocol.ldap_schema.dto import ObjectClassDTO


class ObjectClassRawDisplay:
    @staticmethod
    def get_raw_definition(dto: ObjectClassDTO) -> str:
        if not dto.oid or not dto.name or not dto.kind:
            raise ValueError(
                f"{dto}: Fields 'oid', 'name', and 'kind'"
                " are required for LDAP definition.",
            )
        chunks = ["(", dto.oid, f"NAME '{dto.name}'"]
        if dto.superior_name:
            chunks.append(f"SUP {dto.superior_name}")
        chunks.append(dto.kind)
        if dto.attribute_types_must:
            chunks.append(
                f"MUST ({' $ '.join(dto.attribute_types_must)} )",
            )
        if dto.attribute_types_may:
            chunks.append(
                f"MAY ({' $ '.join(dto.attribute_types_may)} )",
            )
        chunks.append(")")
        return " ".join(chunks)

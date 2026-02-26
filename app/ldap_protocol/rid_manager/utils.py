"""RID Manager utils."""


def create_qword(lower: int, upper: int) -> int:
    """Create QWORD (64-bit) from two DWORDs (32-bit each)."""
    if lower < 0 or lower > 0xFFFFFFFF:
        raise ValueError(f"Lower boundary out of range: {lower}")
    if upper < 0 or upper > 0xFFFFFFFF:
        raise ValueError(f"Upper boundary out of range: {upper}")

    qword = (upper << 32) | lower

    return qword

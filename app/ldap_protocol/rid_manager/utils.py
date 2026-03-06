"""RID Manager utils."""


def to_qword(lower: int, upper: int) -> int:
    """Create QWORD (64-bit) from two DWORDs (32-bit each)."""
    if lower < 0 or lower > 0xFFFFFFFF:
        raise ValueError(f"Lower boundary out of range: {lower}")
    if upper < 0 or upper > 0xFFFFFFFF:
        raise ValueError(f"Upper boundary out of range: {upper}")

    qword = (upper << 32) | lower

    return qword


def from_qword(qword: int) -> tuple[int, int]:
    """Split QWORD (64-bit) into two DWORDs (lower, upper)."""
    if qword < 0 or qword > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"QWORD out of range: {qword}")

    lower = qword & 0xFFFFFFFF
    upper = (qword >> 32) & 0xFFFFFFFF
    return lower, upper

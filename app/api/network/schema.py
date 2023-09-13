"""Network models."""

from ipaddress import IPv4Address, IPv4Interface, summarize_address_range

from pydantic import BaseModel, Field, validator


class Policy(BaseModel):
    """Network Policy model."""

    name: str = Field(..., example='local network')
    netmask: IPv4Interface | tuple[IPv4Address, IPv4Address] = Field(
        ..., example="172.0.0.0/8")

    @validator('netmask')
    def validate_range(cls, value):  # noqa: N805
        """Validate range or return pure value."""
        if isinstance(value, tuple):
            return list(summarize_address_range(value[0], value[1]))[0]
        return value


class PolicyResponse(BaseModel):
    """Network Policy model."""

    id: int  # noqa
    name: str
    netmask: IPv4Interface
    enabled: bool

    class Config:  # noqa
        orm_mode = True

"""Network models."""

from ipaddress import IPv4Address, IPv4Interface, summarize_address_range

from pydantic import BaseModel, Field, validator


class Policy(BaseModel):
    """Network Policy model."""

    name: str = Field(..., example='local network', max_length=100)
    netmasks: list[IPv4Interface | tuple[IPv4Address, IPv4Address]] = Field(
        ..., example="172.0.0.0/8")

    @validator('netmasks')
    def validate_range(cls, value):  # noqa: N805
        """Validate range or return networks range."""
        values = []
        for item in value:
            if isinstance(item, tuple):
                values.extend(list(summarize_address_range(item[0], item[1])))
            else:
                values.append(item)
        return values


class PolicyResponse(BaseModel):
    """Network Policy model for response."""

    id: int  # noqa
    name: str
    netmasks: list[IPv4Interface]
    enabled: bool

    class Config:  # noqa
        orm_mode = True


class PolicyUpdate(BaseModel):
    """Update request."""

    id: int  # noqa
    is_enabled: bool

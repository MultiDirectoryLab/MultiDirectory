"""Constants for the LDF files validator."""

from enum import IntEnum, StrEnum


class VersionOperatingSystemMappings(StrEnum):
    """https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/find-active-directory-schema?tabs=gui#mapping-the-objectversion-attribute."""

    SCH91 = "Windows Server 2025"
    SCH88_WS22 = "Windows Server 2022"
    SCH88_WS19 = "Windows Server 2019"
    SCH87 = "Windows Server 2016"
    SCH69 = "Windows Server 2012 R2"
    SCH56 = "Windows Server 2012"
    SCH47 = "Windows Server 2008 R2"
    SCH44 = "Windows Server 2008 RTM"
    SCH31 = "Windows Server 2003 R2"
    SCH30 = "Windows Server 2003 RTM, Windows 2003 Service Pack 1, Windows 2003 Service Pack 2"  # noqa: E501


class OperatingSystemVersionMappings(IntEnum):
    """https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/find-active-directory-schema?tabs=gui#mapping-the-objectversion-attribute."""

    WINDOWS_SERVER_2025 = 91
    WINDOWS_SERVER_2022_2019 = 88
    WINDOWS_SERVER_2016 = 87
    WINDOWS_SERVER_2012_R2 = 69
    WINDOWS_SERVER_2012 = 56
    WINDOWS_SERVER_2008_R2 = 47
    WINDOWS_SERVER_2008_RTM = 44
    WINDOWS_SERVER_2003_R2 = 31
    WINDOWS_SERVER_2003_RTM_SERVPACK_1_SERVPACK_2 = 30

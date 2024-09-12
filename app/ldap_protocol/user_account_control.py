"""userAccountControl attribute handling.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from enum import IntFlag


class UserAccountControlFlag(IntFlag):
    """userAccountControl flags mapping.

    hex(int)
    # -- 0x1(1) reserved --
    ACCOUNTDISABLE=0x2(2)
    # -- 0x8(8) reserved --
    # -- 0x10(16) reserved --
    # -- 0x20(32) reserved --
    # -- 0x40(64) reserved --
    # -- 0x80(128) reserved --
    # -- 0x100(256) reserved --
    NORMAL_ACCOUNT=0x200(512)
    # -- 0x800(2048) reserved --
    WORKSTATION_TRUST_ACCOUNT=0x1000(4096)
    # -- 0x2000(8192) reserved --
    # -- 0x10000(65536) reserved --
    # -- 0x20000(131072) reserved --
    # -- 0x40000(262144) reserved --
    # -- 0x80000(524288) reserved --
    # -- 0x100000(1048576) reserved --
    # -- 0x200000(2097152) reserved --
    # -- 0x400000(4194304) reserved --
    # -- 0x800000(8388608) reserved --
    # -- 0x1000000(16777216) reserved --
    # -- 0x4000000(67108864) reserved --
    """

    ACCOUNTDISABLE = 0x2
    NORMAL_ACCOUNT = 0x200
    WORKSTATION_TRUST_ACCOUNT = 0x1000

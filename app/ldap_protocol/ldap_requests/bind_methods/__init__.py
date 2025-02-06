"""Bind methods.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .base import (
    AbstractLDAPAuth,
    LDAPBindErrors,
    SaslAuthentication,
    SASLMethod,
    get_bad_response,
)
from .sasl_gssapi import GSSAPISL, GSSAPIAuthStatus, SaslGSSAPIAuthentication
from .sasl_plain import SaslPLAINAuthentication
from .simple import SimpleAuthentication

sasl_mechanism: list[type[SaslAuthentication]] = [
    SaslPLAINAuthentication,
    SaslGSSAPIAuthentication,
]

sasl_mechanism_map: dict[SASLMethod, type[SaslAuthentication]] = {
    request.mechanism: request for request in sasl_mechanism
}

__all__ = [
    "get_bad_response",
    "sasl_mechanism_map",
    "AbstractLDAPAuth",
    "SASLMethod",
    "SaslAuthentication",
    "SaslGSSAPIAuthentication",
    "SaslPLAINAuthentication",
    "SimpleAuthentication",
    "GSSAPIAuthStatus",
    "GSSAPISL",
    "LDAPBindErrors",
]

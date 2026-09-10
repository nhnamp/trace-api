from __future__ import annotations

from enum import Enum


class EdgeType(str, Enum):
    HAS_METHOD = "has_method"
    HAS_PARAMETER = "has_parameter"
    REQUIRES_AUTH = "requires_auth"
    REQUIRES_ROLE = "requires_role"
    PRODUCED_RESPONSE = "produced_response"
    HAS_WEAKNESS = "has_weakness"
    TARGETS = "targets"

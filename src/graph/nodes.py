from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class NodeType(str, Enum):
    ENDPOINT = "endpoint"
    METHOD = "method"
    PARAMETER = "parameter"
    AUTH_SCHEME = "auth_scheme"
    ROLE = "role"
    RESPONSE = "response"
    WEAKNESS = "weakness"
    EXPLOIT_HYPOTHESIS = "exploit_hypothesis"
    PRODUCT = "product"


class GraphNode(BaseModel):
    node_id: str
    node_type: NodeType
    properties: dict = {}

    def label(self) -> str:
        if self.node_type == NodeType.ENDPOINT:
            return self.properties.get("path", self.node_id)
        if self.node_type == NodeType.METHOD:
            return self.properties.get("http_method", self.node_id)
        if self.node_type == NodeType.PARAMETER:
            return self.properties.get("name", self.node_id)
        if self.node_type == NodeType.PRODUCT:
            name = self.properties.get("name", self.node_id)
            version = self.properties.get("version", "")
            return f"{name} {version}".strip()
        return self.node_id

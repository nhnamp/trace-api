from __future__ import annotations

import networkx as nx
import structlog

from src.graph.edges import EdgeType
from src.graph.nodes import GraphNode, NodeType

logger = structlog.get_logger(__name__)


class APIAssetGraph:
    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def add_node(self, node: GraphNode) -> None:
        self.graph.add_node(
            node.node_id,
            node_type=node.node_type.value,
            properties=node.properties,
        )

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        properties: dict | None = None,
    ) -> None:
        self.graph.add_edge(
            source_id,
            target_id,
            edge_type=edge_type.value,
            **(properties or {}),
        )

    def has_node(self, node_id: str) -> bool:
        return self.graph.has_node(node_id)

    def get_node(self, node_id: str) -> dict | None:
        if node_id not in self.graph:
            return None
        return dict(self.graph.nodes[node_id])

    def get_nodes_by_type(self, node_type: NodeType) -> list[dict]:
        return [
            {"node_id": n, **d}
            for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == node_type.value
        ]

    def get_neighbors(
        self, node_id: str, edge_type: EdgeType | None = None
    ) -> list[dict]:
        if node_id not in self.graph:
            return []
        result = []
        for _, target, data in self.graph.out_edges(node_id, data=True):
            if edge_type is None or data.get("edge_type") == edge_type.value:
                node_data = dict(self.graph.nodes[target])
                result.append({"node_id": target, **node_data})
        return result

    def get_endpoints(self) -> list[dict]:
        return self.get_nodes_by_type(NodeType.ENDPOINT)

    def get_weaknesses(self) -> list[dict]:
        return self.get_nodes_by_type(NodeType.WEAKNESS)

    def get_hypotheses(self) -> list[dict]:
        return self.get_nodes_by_type(NodeType.EXPLOIT_HYPOTHESIS)

    def get_products(self) -> list[dict]:
        return self.get_nodes_by_type(NodeType.PRODUCT)

    @property
    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    def summary(self) -> str:
        lines = [
            f"API Asset Graph: {self.node_count} nodes, {self.edge_count} edges"
        ]

        products = self.get_products()
        if products:
            lines.append(f"\nProducts/Services ({len(products)}):")
            for p in products:
                props = p.get("properties", {})
                name = props.get("name", "?")
                version = props.get("version", "")
                confidence = props.get("confidence", "?")
                label = f"{name} {version}".strip()
                lines.append(f"  {label} (confidence: {confidence})")

        endpoints = self.get_endpoints()
        if endpoints:
            lines.append(f"\nEndpoints ({len(endpoints)}):")
            for ep in endpoints:
                props = ep.get("properties", {})
                path = props.get("path", ep["node_id"])
                methods = [
                    n.get("properties", {}).get("http_method", "?")
                    for n in self.get_neighbors(ep["node_id"], EdgeType.HAS_METHOD)
                ]
                methods_str = ", ".join(methods) if methods else "unknown"
                access = props.get("access")
                if access == "bypass-reachable":
                    vector = props.get("bypass_vector", "?")
                    lines.append(
                        f"  {path} [{methods_str}] (BYPASS-REACHABLE — protected content "
                        f"reached via traversal vector '{vector}'; target this exact path)"
                    )
                elif access == "protected":
                    baseline = props.get("baseline_status", "?")
                    lines.append(
                        f"  {path} [{methods_str}] (PROTECTED — direct access returns "
                        f"{baseline}; a bypass must change this)"
                    )
                else:
                    lines.append(f"  {path} [{methods_str}]")

        weaknesses = self.get_weaknesses()
        if weaknesses:
            lines.append(f"\nWeaknesses ({len(weaknesses)}):")
            for w in weaknesses:
                wtype = w.get("properties", {}).get("type", "unknown")
                confidence = w.get("properties", {}).get("confidence", "?")
                lines.append(f"  {wtype} (confidence: {confidence})")

        hypotheses = self.get_hypotheses()
        if hypotheses:
            lines.append(f"\nExploit Hypotheses ({len(hypotheses)}):")
            for h in hypotheses:
                desc = h.get("properties", {}).get("description", h["node_id"])
                lines.append(f"  {desc}")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        return nx.node_link_data(self.graph)

    @classmethod
    def from_dict(cls, data: dict) -> APIAssetGraph:
        g = cls()
        if data:
            g.graph = nx.node_link_graph(data)
        return g

"""Graph node and relationship models for KubePath."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from kubepath.models.enums import NodeType, RelationType, RiskLevel


@dataclass
class GraphNode:
    """Represents a node in the attack graph."""
    node_type: NodeType
    name: str
    properties: dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.INFO
    uid: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Optional context
    namespace: str | None = None
    cluster: str | None = None
    cloud_provider: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for Neo4j storage."""
        data = {
            "uid": self.uid,
            "node_type": self.node_type.value,
            "name": self.name,
            "risk_level": self.risk_level.value,
        }
        if self.namespace:
            data["namespace"] = self.namespace
        if self.cluster:
            data["cluster"] = self.cluster
        if self.cloud_provider:
            data["cloud_provider"] = self.cloud_provider
        # Flatten properties (only primitives for Neo4j)
        for k, v in self.properties.items():
            if isinstance(v, (str, int, float, bool)):
                data[f"prop_{k}"] = v
            elif isinstance(v, list) and all(isinstance(i, str) for i in v):
                data[f"prop_{k}"] = v
        return data

    def to_cytoscape(self) -> dict[str, Any]:
        """Serialize to Cytoscape.js node format."""
        return {
            "data": {
                "id": self.uid,
                "label": self.name,
                "node_type": self.node_type.value,
                "risk_level": self.risk_level.value,
                "namespace": self.namespace or "",
                "cluster": self.cluster or "",
                "cloud_provider": self.cloud_provider or "",
                **{k: str(v) for k, v in self.properties.items()
                   if isinstance(v, (str, int, float, bool))},
            }
        }


@dataclass
class GraphEdge:
    """Represents a relationship (edge) in the attack graph."""
    source_uid: str
    target_uid: str
    relation_type: RelationType
    properties: dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.INFO
    uid: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Attack context
    description: str = ""
    is_attack_edge: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for Neo4j storage."""
        data = {
            "uid": self.uid,
            "relation_type": self.relation_type.value,
            "risk_level": self.risk_level.value,
            "description": self.description,
            "is_attack_edge": self.is_attack_edge,
        }
        for k, v in self.properties.items():
            if isinstance(v, (str, int, float, bool)):
                data[f"prop_{k}"] = v
        return data

    def to_cytoscape(self) -> dict[str, Any]:
        """Serialize to Cytoscape.js edge format."""
        return {
            "data": {
                "id": self.uid,
                "source": self.source_uid,
                "target": self.target_uid,
                "relation_type": self.relation_type.value,
                "risk_level": self.risk_level.value,
                "label": self.relation_type.value.replace("_", " "),
                "description": self.description,
                "is_attack_edge": self.is_attack_edge,
            }
        }


@dataclass
class AttackPath:
    """Represents a computed attack path through the graph."""
    path_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.INFO
    score: float = 0.0
    description: str = ""
    hops: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to API response format."""
        return {
            "path_id": self.path_id,
            "risk_level": self.risk_level.value,
            "score": self.score,
            "description": self.description,
            "hops": self.hops,
            "nodes": [n.to_cytoscape() for n in self.nodes],
            "edges": [e.to_cytoscape() for e in self.edges],
        }


@dataclass
class Finding:
    """A security finding / misconfiguration discovered during analysis."""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    risk_level: RiskLevel = RiskLevel.INFO
    category: str = ""  # e.g., "RBAC", "Network", "IAM"
    affected_resources: list[str] = field(default_factory=list)
    remediation: str = ""
    attack_paths: list[AttackPath] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to API response format."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "category": self.category,
            "affected_resources": self.affected_resources,
            "remediation": self.remediation,
            "attack_paths": [p.to_dict() for p in self.attack_paths],
        }

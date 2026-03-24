"""Base interface for data ingestion engines."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from kubepath.database.neo4j_client import neo4j_client
from kubepath.models.graph import GraphNode, GraphEdge

logger = logging.getLogger(__name__)


class BaseIngestor(ABC):
    """Abstract base class for all data ingestion engines."""

    def __init__(self):
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []
        self.stats: dict[str, int] = {}

    @abstractmethod
    async def ingest(self, **kwargs) -> dict[str, Any]:
        """Run the ingestion pipeline. Returns stats."""
        ...

    @abstractmethod
    async def ingest_from_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Run ingestion from provided JSON data. Returns stats."""
        ...

    async def persist(self) -> dict[str, int]:
        """Persist all collected nodes and edges to Neo4j."""
        node_dicts = [n.to_dict() for n in self.nodes]
        edge_dicts = [
            {
                "source_uid": e.source_uid,
                "target_uid": e.target_uid,
                "rel_data": e.to_dict(),
            }
            for e in self.edges
        ]

        node_count = await neo4j_client.create_nodes_batch(node_dicts)
        edge_count = await neo4j_client.create_relationships_batch(edge_dicts)

        logger.info("Persisted %d nodes and %d edges", node_count, edge_count)
        return {"nodes_created": node_count, "edges_created": edge_count}

    def _add_node(self, node: GraphNode) -> GraphNode:
        """Register a node and return it."""
        self.nodes.append(node)
        return node

    def _add_edge(self, edge: GraphEdge) -> GraphEdge:
        """Register an edge and return it."""
        self.edges.append(edge)
        return edge

    def reset(self) -> None:
        """Clear collected nodes and edges."""
        self.nodes.clear()
        self.edges.clear()
        self.stats.clear()

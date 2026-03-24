"""Neo4j database client for KubePath."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from neo4j import AsyncGraphDatabase, AsyncDriver

from kubepath.config import settings
from kubepath.models.enums import NodeType

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Async Neo4j database client with connection pooling."""

    _driver: AsyncDriver | None = None

    async def connect(self) -> None:
        """Initialize the Neo4j driver."""
        if self._driver is not None:
            return
        self._driver = AsyncGraphDatabase.driver(
            settings.neo4j.uri,
            auth=(settings.neo4j.user, settings.neo4j.password),
            max_connection_pool_size=settings.neo4j.max_connection_pool_size,
        )
        logger.info("Connected to Neo4j at %s", settings.neo4j.uri)
        await self._ensure_indexes()

    async def disconnect(self) -> None:
        """Close the Neo4j driver."""
        if self._driver:
            await self._driver.close()
            self._driver = None
            logger.info("Disconnected from Neo4j")

    @property
    def driver(self) -> AsyncDriver:
        if self._driver is None:
            raise RuntimeError("Neo4j client is not connected. Call connect() first.")
        return self._driver

    @asynccontextmanager
    async def session(self):
        """Get an async session."""
        async with self.driver.session(database=settings.neo4j.database) as s:
            yield s

    # ── Schema & Index Management ──────────────────────────────────────

    async def _ensure_indexes(self) -> None:
        """Create constraints and indexes for performance."""
        queries = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:GraphNode) REQUIRE n.uid IS UNIQUE",
            "CREATE INDEX IF NOT EXISTS FOR (n:GraphNode) ON (n.node_type)",
            "CREATE INDEX IF NOT EXISTS FOR (n:GraphNode) ON (n.name)",
            "CREATE INDEX IF NOT EXISTS FOR (n:GraphNode) ON (n.namespace)",
            "CREATE INDEX IF NOT EXISTS FOR (n:GraphNode) ON (n.risk_level)",
        ]
        async with self.session() as session:
            for q in queries:
                try:
                    await session.run(q)
                except Exception as e:
                    logger.warning("Index creation warning: %s", e)
        logger.info("Neo4j indexes ensured")

    # ── Node Operations ────────────────────────────────────────────────

    async def create_node(self, node_data: dict[str, Any]) -> str:
        """Create or merge a node in Neo4j. Returns the UID."""
        node_type = node_data.get("node_type", "Unknown")
        uid = node_data["uid"]

        query = """
        MERGE (n:GraphNode {uid: $uid})
        SET n += $props
        SET n:%s
        RETURN n.uid AS uid
        """ % _safe_label(node_type)

        async with self.session() as session:
            result = await session.run(query, uid=uid, props=node_data)
            record = await result.single()
            return record["uid"] if record else uid

    async def create_nodes_batch(self, nodes: list[dict[str, Any]]) -> int:
        """Batch create nodes for performance. Returns count."""
        if not nodes:
            return 0
        query = """
        UNWIND $nodes AS node_data
        MERGE (n:GraphNode {uid: node_data.uid})
        SET n += node_data
        RETURN count(n) AS cnt
        """
        async with self.session() as session:
            result = await session.run(query, nodes=nodes)
            record = await result.single()
            count = record["cnt"] if record else 0

        # Apply type-specific labels
        for node_data in nodes:
            node_type = node_data.get("node_type", "Unknown")
            label = _safe_label(node_type)
            label_query = f"""
            MATCH (n:GraphNode {{uid: $uid}})
            SET n:{label}
            """
            async with self.session() as session:
                await session.run(label_query, uid=node_data["uid"])

        return count

    async def get_node(self, uid: str) -> dict[str, Any] | None:
        """Get a node by UID."""
        query = "MATCH (n:GraphNode {uid: $uid}) RETURN n"
        async with self.session() as session:
            result = await session.run(query, uid=uid)
            record = await result.single()
            if record:
                return dict(record["n"])
        return None

    async def get_node_neighbors(self, uid: str) -> dict[str, Any]:
        """Get a node and all its direct neighbors."""
        query = """
        MATCH (n:GraphNode {uid: $uid})
        OPTIONAL MATCH (n)-[r]-(m:GraphNode)
        RETURN n, collect(DISTINCT {node: m, rel: r, direction: CASE
            WHEN startNode(r) = n THEN 'outgoing'
            ELSE 'incoming'
        END}) AS neighbors
        """
        async with self.session() as session:
            result = await session.run(query, uid=uid)
            record = await result.single()
            if not record:
                return {}
            node = dict(record["n"])
            neighbors = []
            for item in record["neighbors"]:
                if item["node"] is not None:
                    neighbors.append({
                        "node": dict(item["node"]),
                        "relationship": dict(item["rel"]) if item["rel"] else {},
                        "direction": item["direction"],
                    })
            return {"node": node, "neighbors": neighbors}

    # ── Relationship Operations ────────────────────────────────────────

    async def create_relationship(
        self,
        source_uid: str,
        target_uid: str,
        rel_data: dict[str, Any],
    ) -> str:
        """Create a relationship between two nodes."""
        rel_type = rel_data.get("relation_type", "RELATED_TO")
        uid = rel_data.get("uid", "")

        query = """
        MATCH (a:GraphNode {uid: $source_uid})
        MATCH (b:GraphNode {uid: $target_uid})
        MERGE (a)-[r:%s {uid: $uid}]->(b)
        SET r += $props
        RETURN r.uid AS uid
        """ % _safe_label(rel_type)

        async with self.session() as session:
            result = await session.run(
                query, source_uid=source_uid, target_uid=target_uid,
                uid=uid, props=rel_data,
            )
            record = await result.single()
            return record["uid"] if record else uid

    async def create_relationships_batch(self, relationships: list[dict[str, Any]]) -> int:
        """Batch create relationships. Each dict must have source_uid, target_uid, and rel_data."""
        count = 0
        for rel in relationships:
            await self.create_relationship(
                rel["source_uid"], rel["target_uid"], rel["rel_data"]
            )
            count += 1
        return count

    # ── Graph Queries ──────────────────────────────────────────────────

    async def get_full_graph(self) -> dict[str, list]:
        """Get all nodes and relationships for visualization."""
        nodes_query = "MATCH (n:GraphNode) RETURN n"
        edges_query = """
        MATCH (a:GraphNode)-[r]->(b:GraphNode)
        RETURN a.uid AS source, b.uid AS target, type(r) AS rel_type, properties(r) AS props
        """
        nodes = []
        edges = []

        async with self.session() as session:
            result = await session.run(nodes_query)
            records = await result.data()
            for record in records:
                node_props = dict(record["n"])
                nodes.append({
                    "data": {
                        "id": node_props.get("uid", ""),
                        "label": node_props.get("name", ""),
                        **{k: v for k, v in node_props.items()
                           if isinstance(v, (str, int, float, bool))},
                    }
                })

        async with self.session() as session:
            result = await session.run(edges_query)
            records = await result.data()
            for record in records:
                props = record.get("props", {}) or {}
                edges.append({
                    "data": {
                        "id": props.get("uid", f"{record['source']}-{record['target']}"),
                        "source": record["source"],
                        "target": record["target"],
                        "relation_type": record["rel_type"],
                        "label": record["rel_type"].replace("_", " "),
                        **{k: v for k, v in props.items()
                           if isinstance(v, (str, int, float, bool))},
                    }
                })

        return {"nodes": nodes, "edges": edges}

    async def find_shortest_paths(
        self,
        source_uid: str,
        target_uid: str,
        max_hops: int = 10,
    ) -> list[dict[str, Any]]:
        """Find shortest paths between two nodes."""
        query = """
        MATCH path = shortestPath(
            (a:GraphNode {uid: $source_uid})-[*1..%d]->(b:GraphNode {uid: $target_uid})
        )
        RETURN [n IN nodes(path) | n] AS nodes,
               [r IN relationships(path) | {
                   source: startNode(r).uid,
                   target: endNode(r).uid,
                   type: type(r),
                   props: properties(r)
               }] AS rels
        LIMIT 5
        """ % max_hops

        paths = []
        async with self.session() as session:
            result = await session.run(
                query, source_uid=source_uid, target_uid=target_uid
            )
            records = await result.data()
            for record in records:
                path_nodes = []
                for n in record["nodes"]:
                    path_nodes.append(dict(n))
                path_rels = record["rels"]
                paths.append({"nodes": path_nodes, "relationships": path_rels})

        return paths

    async def find_all_attack_paths(
        self,
        target_type: str = "ClusterAdmin",
        max_hops: int = 8,
    ) -> list[dict[str, Any]]:
        """Find all paths leading to high-value targets (e.g., ClusterAdmin)."""
        query = """
        MATCH path = (start:GraphNode)-[*1..%d]->(target:GraphNode)
        WHERE target.node_type = $target_type
          AND start.uid <> target.uid
        WITH path, start, target,
             length(path) AS hops,
             [r IN relationships(path) | r.risk_level] AS risk_levels
        RETURN
            start.uid AS source_uid,
            start.name AS source_name,
            start.node_type AS source_type,
            target.uid AS target_uid,
            target.name AS target_name,
            [n IN nodes(path) | {uid: n.uid, name: n.name, node_type: n.node_type, risk_level: n.risk_level}] AS nodes,
            [r IN relationships(path) | {
                source: startNode(r).uid,
                target: endNode(r).uid,
                type: type(r),
                risk_level: r.risk_level,
                description: r.description
            }] AS rels,
            hops
        ORDER BY hops ASC
        LIMIT 20
        """ % max_hops

        paths = []
        async with self.session() as session:
            result = await session.run(query, target_type=target_type)
            records = await result.data()
            for record in records:
                paths.append({
                    "source": {"uid": record["source_uid"], "name": record["source_name"], "type": record["source_type"]},
                    "target": {"uid": record["target_uid"], "name": record["target_name"]},
                    "nodes": record["nodes"],
                    "relationships": record["rels"],
                    "hops": record["hops"],
                })
        return paths

    async def get_stats(self) -> dict[str, Any]:
        """Get graph statistics."""
        query = """
        MATCH (n:GraphNode)
        WITH n.node_type AS node_type, count(n) AS cnt
        RETURN collect({type: node_type, count: cnt}) AS type_counts
        """
        edge_query = """
        MATCH ()-[r]->()
        RETURN count(r) AS total_edges
        """
        risk_query = """
        MATCH (n:GraphNode)
        WHERE n.risk_level IS NOT NULL
        WITH n.risk_level AS risk, count(n) AS cnt
        RETURN collect({risk: risk, count: cnt}) AS risk_counts
        """

        stats: dict[str, Any] = {"total_nodes": 0, "total_edges": 0, "node_types": {}, "risk_breakdown": {}}
        async with self.session() as session:
            result = await session.run(query)
            record = await result.single()
            if record:
                for item in record["type_counts"]:
                    stats["node_types"][item["type"]] = item["count"]
                    stats["total_nodes"] += item["count"]

            result = await session.run(edge_query)
            record = await result.single()
            if record:
                stats["total_edges"] = record["total_edges"]

            result = await session.run(risk_query)
            record = await result.single()
            if record:
                for item in record["risk_counts"]:
                    stats["risk_breakdown"][item["risk"]] = item["count"]

        return stats

    # ── Cleanup ────────────────────────────────────────────────────────

    async def clear_graph(self) -> int:
        """Delete all nodes and relationships. Returns count deleted."""
        query = """
        MATCH (n)
        WITH n LIMIT 10000
        DETACH DELETE n
        RETURN count(n) AS deleted
        """
        total = 0
        while True:
            async with self.session() as session:
                result = await session.run(query)
                record = await result.single()
                deleted = record["deleted"] if record else 0
                total += deleted
                if deleted == 0:
                    break
        logger.info("Cleared %d nodes from graph", total)
        return total


def _safe_label(value: str) -> str:
    """Sanitize a string for use as a Neo4j label."""
    return "".join(c if c.isalnum() or c == "_" else "_" for c in value)


# Global client instance
neo4j_client = Neo4jClient()

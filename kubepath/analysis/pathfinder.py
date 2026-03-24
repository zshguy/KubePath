"""Attack path finder — graph traversal and path discovery."""

from __future__ import annotations

import logging
from typing import Any

from kubepath.database.neo4j_client import neo4j_client
from kubepath.models.enums import RiskLevel

logger = logging.getLogger(__name__)


class PathFinder:
    """Discovers attack paths through the graph."""

    async def find_paths_to_admin(self, max_hops: int = 8) -> list[dict[str, Any]]:
        """Find all paths from any node to ClusterAdmin or high-privilege IAM roles."""
        paths = await neo4j_client.find_all_attack_paths(
            target_type="ClusterAdmin", max_hops=max_hops
        )

        # Also find paths to critical IAM roles
        iam_paths = await neo4j_client.find_all_attack_paths(
            target_type="IAMRole", max_hops=max_hops
        )
        # Filter IAM paths to only CRITICAL risk targets
        for p in iam_paths:
            target_nodes = [n for n in p.get("nodes", []) if n.get("uid") == p.get("target", {}).get("uid")]
            if target_nodes and target_nodes[0].get("risk_level") == RiskLevel.CRITICAL.value:
                paths.append(p)

        # Score and sort paths
        scored_paths = []
        for path in paths:
            score = self._score_path(path)
            path["score"] = score
            path["risk_level"] = self._path_risk_level(score)
            scored_paths.append(path)

        scored_paths.sort(key=lambda p: p["score"], reverse=True)
        return scored_paths

    async def find_path_between(
        self, source_uid: str, target_uid: str, max_hops: int = 10
    ) -> list[dict[str, Any]]:
        """Find shortest paths between two specific nodes."""
        paths = await neo4j_client.find_shortest_paths(source_uid, target_uid, max_hops)

        scored = []
        for path in paths:
            score = self._score_raw_path(path)
            path["score"] = score
            path["risk_level"] = self._path_risk_level(score)
            scored.append(path)

        scored.sort(key=lambda p: p["score"], reverse=True)
        return scored

    async def find_critical_nodes(self) -> list[dict[str, Any]]:
        """Find nodes that appear in the most attack paths (chokepoints)."""
        query = """
        MATCH path = (start:GraphNode)-[*1..6]->(target:GraphNode)
        WHERE target.node_type = 'ClusterAdmin'
          AND start.uid <> target.uid
        WITH nodes(path) AS path_nodes
        UNWIND path_nodes AS n
        WITH n
        WHERE n.node_type <> 'ClusterAdmin'
        WITH n, count(*) AS path_count
        RETURN n.uid AS uid, n.name AS name, n.node_type AS node_type,
               n.risk_level AS risk_level, path_count
        ORDER BY path_count DESC
        LIMIT 20
        """
        results = []
        async with neo4j_client.session() as session:
            result = await session.run(query)
            records = await result.data()
            for record in records:
                results.append({
                    "uid": record["uid"],
                    "name": record["name"],
                    "node_type": record["node_type"],
                    "risk_level": record["risk_level"],
                    "path_count": record["path_count"],
                    "is_chokepoint": record["path_count"] > 2,
                })
        return results

    async def find_external_entry_points(self) -> list[dict[str, Any]]:
        """Find externally accessible entry points."""
        query = """
        MATCH (n:GraphNode)
        WHERE n.node_type IN ['Service', 'Internet', 'External']
           OR (n.node_type = 'Pod' AND n.prop_host_network = true)
           OR (n.node_type = 'Service' AND n.prop_external = true)
        RETURN n.uid AS uid, n.name AS name, n.node_type AS node_type,
               n.risk_level AS risk_level, n.namespace AS namespace
        """
        results = []
        async with neo4j_client.session() as session:
            result = await session.run(query)
            records = await result.data()
            for record in records:
                results.append(dict(record))
        return results

    # ── Scoring Helpers ────────────────────────────────────────────

    def _score_path(self, path: dict) -> float:
        """Score a path based on hop count and node risk levels."""
        hops = path.get("hops", len(path.get("nodes", [])))
        nodes = path.get("nodes", [])

        # Base score: fewer hops = higher risk
        base_score = max(0, 100 - (hops * 10))

        # Bonus for high-risk nodes in path
        risk_bonus = 0
        for node in nodes:
            risk = node.get("risk_level", "INFO")
            if risk == "CRITICAL":
                risk_bonus += 25
            elif risk == "HIGH":
                risk_bonus += 15
            elif risk == "MEDIUM":
                risk_bonus += 5

        # Bonus for attack edges
        rels = path.get("relationships", [])
        for rel in rels:
            if rel.get("risk_level") == "CRITICAL":
                risk_bonus += 20
            elif rel.get("risk_level") == "HIGH":
                risk_bonus += 10

        return min(100.0, base_score + risk_bonus)

    def _score_raw_path(self, path: dict) -> float:
        """Score a raw path (from shortestPath query)."""
        nodes = path.get("nodes", [])
        hops = len(nodes) - 1 if nodes else 0
        base_score = max(0, 100 - (hops * 10))

        risk_bonus = 0
        for node in nodes:
            risk = node.get("risk_level", "INFO")
            if risk == "CRITICAL":
                risk_bonus += 25
            elif risk == "HIGH":
                risk_bonus += 15

        return min(100.0, base_score + risk_bonus)

    def _path_risk_level(self, score: float) -> str:
        """Map a score to a risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL.value
        elif score >= 60:
            return RiskLevel.HIGH.value
        elif score >= 40:
            return RiskLevel.MEDIUM.value
        elif score >= 20:
            return RiskLevel.LOW.value
        return RiskLevel.INFO.value


# Singleton
pathfinder = PathFinder()

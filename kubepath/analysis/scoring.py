"""Risk scoring engine for KubePath."""

from __future__ import annotations

import logging
from typing import Any

from kubepath.database.neo4j_client import neo4j_client
from kubepath.models.enums import RiskLevel, RISK_LEVEL_ORDER

logger = logging.getLogger(__name__)


class RiskScorer:
    """Computes overall risk scores for the cluster/account."""

    async def compute_overall_score(self) -> dict[str, Any]:
        """Compute the overall security risk score (0-100, higher = worse)."""
        stats = await neo4j_client.get_stats()

        # Factor 1: Proportion of critical/high risk nodes
        total_nodes = stats.get("total_nodes", 0)
        risk_breakdown = stats.get("risk_breakdown", {})
        critical_count = risk_breakdown.get("CRITICAL", 0)
        high_count = risk_breakdown.get("HIGH", 0)
        medium_count = risk_breakdown.get("MEDIUM", 0)

        if total_nodes == 0:
            return {"score": 0, "grade": "N/A", "factors": [], "summary": "No data ingested"}

        risk_ratio = (critical_count * 4 + high_count * 2 + medium_count) / (total_nodes * 4)
        risk_factor = min(40, risk_ratio * 40)

        # Factor 2: Number of attack paths to admin
        from kubepath.analysis.pathfinder import pathfinder
        attack_paths = await pathfinder.find_paths_to_admin(max_hops=6)
        path_count = len(attack_paths)
        path_factor = min(30, path_count * 5)

        # Factor 3: Entry points
        entry_points = await pathfinder.find_external_entry_points()
        entry_factor = min(15, len(entry_points) * 3)

        # Factor 4: Chokepoints
        chokepoints = await pathfinder.find_critical_nodes()
        chokepoint_factor = min(15, len([c for c in chokepoints if c["is_chokepoint"]]) * 5)

        total_score = min(100, risk_factor + path_factor + entry_factor + chokepoint_factor)

        # Determine grade
        if total_score >= 80:
            grade = "F"
        elif total_score >= 60:
            grade = "D"
        elif total_score >= 40:
            grade = "C"
        elif total_score >= 20:
            grade = "B"
        else:
            grade = "A"

        factors = [
            {"name": "High-Risk Nodes", "score": round(risk_factor, 1), "max": 40,
             "detail": f"{critical_count} critical, {high_count} high-risk nodes out of {total_nodes} total"},
            {"name": "Attack Paths", "score": round(path_factor, 1), "max": 30,
             "detail": f"{path_count} attack paths to admin-level targets"},
            {"name": "Entry Points", "score": round(entry_factor, 1), "max": 15,
             "detail": f"{len(entry_points)} externally accessible entry points"},
            {"name": "Chokepoints", "score": round(chokepoint_factor, 1), "max": 15,
             "detail": f"{len([c for c in chokepoints if c['is_chokepoint']])} critical chokepoints"},
        ]

        summary = self._generate_summary(grade, total_score, critical_count, path_count)

        return {
            "score": round(total_score, 1),
            "grade": grade,
            "risk_level": self._score_to_risk(total_score).value,
            "factors": factors,
            "summary": summary,
            "stats": stats,
        }

    async def get_findings(self) -> list[dict[str, Any]]:
        """Generate security findings based on graph analysis."""
        findings = []

        # 1. Privileged pods
        query = """
        MATCH (n:GraphNode)
        WHERE n.node_type = 'Pod' AND n.prop_privileged = true
        RETURN n.uid AS uid, n.name AS name, n.namespace AS namespace
        """
        async with neo4j_client.session() as session:
            result = await session.run(query)
            records = await result.data()
            if records:
                findings.append({
                    "title": "Privileged Pods Detected",
                    "description": f"{len(records)} pods running in privileged mode can escape to the host",
                    "risk_level": RiskLevel.CRITICAL.value,
                    "category": "Container Security",
                    "affected_resources": [r["name"] for r in records],
                    "remediation": "Remove privileged: true from pod security contexts. Use pod security standards.",
                })

        # 2. Wildcard RBAC roles
        query = """
        MATCH (n:GraphNode)
        WHERE n.node_type IN ['Role', 'ClusterRole']
          AND n.prop_rules_summary CONTAINS '*/*'
        RETURN n.uid AS uid, n.name AS name
        """
        async with neo4j_client.session() as session:
            result = await session.run(query)
            records = await result.data()
            if records:
                findings.append({
                    "title": "Wildcard RBAC Permissions",
                    "description": f"{len(records)} roles with wildcard (*/*) permissions grant unrestricted access",
                    "risk_level": RiskLevel.CRITICAL.value,
                    "category": "RBAC",
                    "affected_resources": [r["name"] for r in records],
                    "remediation": "Replace wildcard permissions with specific resource/verb combinations.",
                })

        # 3. Automounting SA tokens
        query = """
        MATCH (n:GraphNode)
        WHERE n.node_type = 'Pod' AND n.prop_automount_token = true
        RETURN count(n) AS cnt
        """
        async with neo4j_client.session() as session:
            result = await session.run(query)
            record = await result.single()
            cnt = record["cnt"] if record else 0
            if cnt > 0:
                findings.append({
                    "title": "Automatic SA Token Mounting",
                    "description": f"{cnt} pods automatically mount service account tokens",
                    "risk_level": RiskLevel.MEDIUM.value,
                    "category": "Authentication",
                    "affected_resources": [f"{cnt} pods"],
                    "remediation": "Set automountServiceAccountToken: false on pods that don't need API access.",
                })

        # 4. Host-network pods
        query = """
        MATCH (n:GraphNode)
        WHERE n.node_type = 'Pod' AND n.prop_host_network = true
        RETURN n.uid AS uid, n.name AS name
        """
        async with neo4j_client.session() as session:
            result = await session.run(query)
            records = await result.data()
            if records:
                findings.append({
                    "title": "Host Network Access",
                    "description": f"{len(records)} pods running with host network access",
                    "risk_level": RiskLevel.HIGH.value,
                    "category": "Network",
                    "affected_resources": [r["name"] for r in records],
                    "remediation": "Remove hostNetwork: true unless absolutely required.",
                })

        # 5. Externally exposed services
        query = """
        MATCH (n:GraphNode)
        WHERE n.node_type = 'Service' AND n.prop_external = true
        RETURN n.uid AS uid, n.name AS name
        """
        async with neo4j_client.session() as session:
            result = await session.run(query)
            records = await result.data()
            if records:
                findings.append({
                    "title": "Externally Exposed Services",
                    "description": f"{len(records)} services exposed externally via LoadBalancer/NodePort",
                    "risk_level": RiskLevel.MEDIUM.value,
                    "category": "Network",
                    "affected_resources": [r["name"] for r in records],
                    "remediation": "Use ClusterIP + Ingress with TLS where possible.",
                })

        return findings

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        return RiskLevel.INFO

    def _generate_summary(self, grade: str, score: float, critical: int, paths: int) -> str:
        if grade in ("F", "D"):
            return (f"Security posture is POOR (grade {grade}, score {score:.0f}/100). "
                    f"Found {critical} critical-risk resources and {paths} attack paths to cluster admin. "
                    f"Immediate remediation required.")
        elif grade == "C":
            return (f"Security posture is MODERATE (grade {grade}, score {score:.0f}/100). "
                    f"Some significant findings require attention.")
        else:
            return (f"Security posture is GOOD (grade {grade}, score {score:.0f}/100). "
                    f"Minor improvements recommended.")


# Singleton
risk_scorer = RiskScorer()

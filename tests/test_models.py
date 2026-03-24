"""Tests for KubePath data models."""

from kubepath.models.enums import NodeType, RelationType, RiskLevel, RISK_LEVEL_ORDER, NODE_COLORS, NODE_SHAPES
from kubepath.models.graph import GraphNode, GraphEdge, AttackPath, Finding


class TestEnums:
    """Test enum definitions."""

    def test_node_types_exist(self):
        assert NodeType.POD.value == "Pod"
        assert NodeType.SERVICE_ACCOUNT.value == "ServiceAccount"
        assert NodeType.CLUSTER_ADMIN.value == "ClusterAdmin"
        assert NodeType.IAM_USER.value == "IAMUser"
        assert NodeType.IAM_ROLE.value == "IAMRole"

    def test_relation_types_exist(self):
        assert RelationType.BOUND_TO.value == "BOUND_TO"
        assert RelationType.CAN_EXEC_INTO.value == "CAN_EXEC_INTO"
        assert RelationType.CAN_ASSUME.value == "CAN_ASSUME"
        assert RelationType.CAN_PRIVESC.value == "CAN_PRIVESC"

    def test_risk_levels(self):
        assert RiskLevel.CRITICAL.value == "CRITICAL"
        assert RiskLevel.INFO.value == "INFO"
        assert RISK_LEVEL_ORDER[RiskLevel.CRITICAL] > RISK_LEVEL_ORDER[RiskLevel.HIGH]
        assert RISK_LEVEL_ORDER[RiskLevel.HIGH] > RISK_LEVEL_ORDER[RiskLevel.MEDIUM]

    def test_node_colors_coverage(self):
        # Every NodeType should have a color
        for nt in [NodeType.POD, NodeType.SERVICE_ACCOUNT, NodeType.CLUSTER_ROLE,
                    NodeType.IAM_USER, NodeType.IAM_ROLE, NodeType.CLUSTER_ADMIN]:
            assert nt in NODE_COLORS

    def test_node_shapes_coverage(self):
        for nt in [NodeType.POD, NodeType.SERVICE_ACCOUNT, NodeType.CLUSTER_ADMIN]:
            assert nt in NODE_SHAPES


class TestGraphNode:
    """Test GraphNode model."""

    def test_creation(self):
        node = GraphNode(
            node_type=NodeType.POD,
            name="test-pod",
            risk_level=RiskLevel.HIGH,
            namespace="default",
        )
        assert node.name == "test-pod"
        assert node.node_type == NodeType.POD
        assert node.risk_level == RiskLevel.HIGH
        assert node.uid  # Auto-generated

    def test_to_dict(self):
        node = GraphNode(
            node_type=NodeType.POD,
            name="test-pod",
            namespace="default",
            properties={"privileged": True, "container_count": 2},
        )
        d = node.to_dict()
        assert d["node_type"] == "Pod"
        assert d["name"] == "test-pod"
        assert d["namespace"] == "default"
        assert d["prop_privileged"] is True
        assert d["prop_container_count"] == 2

    def test_to_cytoscape(self):
        node = GraphNode(
            node_type=NodeType.SERVICE_ACCOUNT,
            name="web-sa",
            risk_level=RiskLevel.MEDIUM,
        )
        cy = node.to_cytoscape()
        assert cy["data"]["id"] == node.uid
        assert cy["data"]["label"] == "web-sa"
        assert cy["data"]["node_type"] == "ServiceAccount"
        assert cy["data"]["risk_level"] == "MEDIUM"


class TestGraphEdge:
    """Test GraphEdge model."""

    def test_creation(self):
        edge = GraphEdge(
            source_uid="src-1",
            target_uid="tgt-1",
            relation_type=RelationType.CAN_EXEC_INTO,
            risk_level=RiskLevel.CRITICAL,
            description="Can exec into pod",
            is_attack_edge=True,
        )
        assert edge.source_uid == "src-1"
        assert edge.relation_type == RelationType.CAN_EXEC_INTO
        assert edge.is_attack_edge is True

    def test_to_cytoscape(self):
        edge = GraphEdge(
            source_uid="src-1",
            target_uid="tgt-1",
            relation_type=RelationType.RUNS_AS,
        )
        cy = edge.to_cytoscape()
        assert cy["data"]["source"] == "src-1"
        assert cy["data"]["target"] == "tgt-1"
        assert cy["data"]["relation_type"] == "RUNS_AS"


class TestAttackPath:
    """Test AttackPath model."""

    def test_to_dict(self):
        path = AttackPath(
            score=85.0,
            risk_level=RiskLevel.CRITICAL,
            description="Pod → SA → ClusterAdmin",
            hops=3,
        )
        d = path.to_dict()
        assert d["score"] == 85.0
        assert d["risk_level"] == "CRITICAL"
        assert d["hops"] == 3


class TestFinding:
    """Test Finding model."""

    def test_to_dict(self):
        finding = Finding(
            title="Privileged Pods",
            description="Found privileged pods",
            risk_level=RiskLevel.CRITICAL,
            category="Container Security",
            affected_resources=["pod-1", "pod-2"],
            remediation="Remove privileged: true",
        )
        d = finding.to_dict()
        assert d["title"] == "Privileged Pods"
        assert d["risk_level"] == "CRITICAL"
        assert len(d["affected_resources"]) == 2

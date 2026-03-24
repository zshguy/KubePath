"""Tests for KubePath ingestion engines."""

import pytest
from kubepath.ingestion.kubernetes import KubernetesIngestor
from kubepath.ingestion.aws import AWSIngestor
from kubepath.models.enums import NodeType, RelationType, RiskLevel


class TestKubernetesIngestor:
    """Test Kubernetes ingestion logic (without Neo4j)."""

    def test_ingest_collects_nodes(self, minimal_k8s_data):
        """Test that ingestion creates graph nodes from K8s data."""
        ingestor = KubernetesIngestor()
        # Call the internal processing methods (skip persist)
        ingestor._node_map.clear()
        ingestor.nodes.clear()
        ingestor.edges.clear()

        # Manually process data (same as ingest_from_data but without persist)
        from kubepath.models.graph import GraphNode
        cluster_admin = ingestor._add_node(GraphNode(
            node_type=NodeType.CLUSTER_ADMIN,
            name="cluster-admin",
            risk_level=RiskLevel.CRITICAL,
        ))
        ingestor._node_map["cluster-admin"] = cluster_admin

        for ns in minimal_k8s_data.get("namespaces", []):
            ingestor._ingest_namespace(ns, "test")

        for sa in minimal_k8s_data.get("service_accounts", []):
            ingestor._ingest_service_account(sa, "test")

        for pod in minimal_k8s_data.get("pods", []):
            ingestor._ingest_pod(pod, "test")

        for cr in minimal_k8s_data.get("cluster_roles", []):
            ingestor._ingest_role(cr, "test", is_cluster_role=True)

        for crb in minimal_k8s_data.get("cluster_role_bindings", []):
            ingestor._ingest_role_binding(crb, "test", is_cluster_binding=True)

        # Verify nodes created
        node_types = [n.node_type for n in ingestor.nodes]
        assert NodeType.CLUSTER_ADMIN in node_types
        assert NodeType.NAMESPACE in node_types
        assert NodeType.SERVICE_ACCOUNT in node_types
        assert NodeType.POD in node_types
        assert NodeType.CLUSTER_ROLE in node_types

    def test_privileged_pod_detection(self, minimal_k8s_data):
        """Test that privileged pods are detected."""
        ingestor = KubernetesIngestor()
        from kubepath.models.graph import GraphNode
        cluster_admin = ingestor._add_node(GraphNode(
            node_type=NodeType.CLUSTER_ADMIN,
            name="cluster-admin",
            risk_level=RiskLevel.CRITICAL,
        ))
        ingestor._node_map["cluster-admin"] = cluster_admin

        for ns in minimal_k8s_data.get("namespaces", []):
            ingestor._ingest_namespace(ns, "test")
        for sa in minimal_k8s_data.get("service_accounts", []):
            ingestor._ingest_service_account(sa, "test")
        for pod in minimal_k8s_data.get("pods", []):
            ingestor._ingest_pod(pod, "test")

        # Find the web-pod node
        web_pod = next((n for n in ingestor.nodes if n.name == "production/web-pod"), None)
        assert web_pod is not None
        assert web_pod.risk_level == RiskLevel.CRITICAL  # Privileged
        assert web_pod.properties.get("privileged") is True

    def test_cluster_admin_role_detection(self, minimal_k8s_data):
        """Test that cluster-admin role is flagged as critical."""
        ingestor = KubernetesIngestor()
        from kubepath.models.graph import GraphNode
        cluster_admin = ingestor._add_node(GraphNode(
            node_type=NodeType.CLUSTER_ADMIN,
            name="cluster-admin",
            risk_level=RiskLevel.CRITICAL,
        ))
        ingestor._node_map["cluster-admin"] = cluster_admin

        for cr in minimal_k8s_data.get("cluster_roles", []):
            ingestor._ingest_role(cr, "test", is_cluster_role=True)

        admin_role = next((n for n in ingestor.nodes if n.node_type == NodeType.CLUSTER_ROLE), None)
        assert admin_role is not None
        assert admin_role.risk_level == RiskLevel.CRITICAL

    def test_sa_automount_detection(self, minimal_k8s_data):
        """Test that SA token automounting is tracked."""
        ingestor = KubernetesIngestor()
        from kubepath.models.graph import GraphNode
        cluster_admin = ingestor._add_node(GraphNode(
            node_type=NodeType.CLUSTER_ADMIN,
            name="cluster-admin",
            risk_level=RiskLevel.CRITICAL,
        ))
        ingestor._node_map["cluster-admin"] = cluster_admin

        for ns in minimal_k8s_data.get("namespaces", []):
            ingestor._ingest_namespace(ns, "test")

        for sa in minimal_k8s_data.get("service_accounts", []):
            ingestor._ingest_service_account(sa, "test")

        sa_nodes = [n for n in ingestor.nodes if n.node_type == NodeType.SERVICE_ACCOUNT]
        assert len(sa_nodes) > 0
        # All SAs with automount=True should have MEDIUM risk
        for sa in sa_nodes:
            assert sa.properties.get("automount_token") is True

    def test_edge_creation(self, minimal_k8s_data):
        """Test that relationships are created between nodes."""
        ingestor = KubernetesIngestor()
        from kubepath.models.graph import GraphNode
        cluster_admin = ingestor._add_node(GraphNode(
            node_type=NodeType.CLUSTER_ADMIN,
            name="cluster-admin",
            risk_level=RiskLevel.CRITICAL,
        ))
        ingestor._node_map["cluster-admin"] = cluster_admin

        for ns in minimal_k8s_data.get("namespaces", []):
            ingestor._ingest_namespace(ns, "test")
        for sa in minimal_k8s_data.get("service_accounts", []):
            ingestor._ingest_service_account(sa, "test")
        for pod in minimal_k8s_data.get("pods", []):
            ingestor._ingest_pod(pod, "test")

        # Should have created RUNS_AS and IN_NAMESPACE relationships
        rel_types = [e.relation_type for e in ingestor.edges]
        assert RelationType.RUNS_AS in rel_types or RelationType.IN_NAMESPACE in rel_types

    def test_full_sample_data_ingestion(self, sample_k8s_data):
        """Test ingestion of the full sample dataset."""
        ingestor = KubernetesIngestor()
        from kubepath.models.graph import GraphNode
        cluster_admin = ingestor._add_node(GraphNode(
            node_type=NodeType.CLUSTER_ADMIN,
            name="cluster-admin",
            risk_level=RiskLevel.CRITICAL,
        ))
        ingestor._node_map["cluster-admin"] = cluster_admin

        for ns in sample_k8s_data.get("namespaces", []):
            ingestor._ingest_namespace(ns, "test")
        for sa in sample_k8s_data.get("service_accounts", []):
            ingestor._ingest_service_account(sa, "test")
        for pod in sample_k8s_data.get("pods", []):
            ingestor._ingest_pod(pod, "test")
        for role in sample_k8s_data.get("roles", []):
            ingestor._ingest_role(role, "test", is_cluster_role=False)
        for cr in sample_k8s_data.get("cluster_roles", []):
            ingestor._ingest_role(cr, "test", is_cluster_role=True)
        for rb in sample_k8s_data.get("role_bindings", []):
            ingestor._ingest_role_binding(rb, "test", is_cluster_binding=False)
        for crb in sample_k8s_data.get("cluster_role_bindings", []):
            ingestor._ingest_role_binding(crb, "test", is_cluster_binding=True)
        for svc in sample_k8s_data.get("services", []):
            ingestor._ingest_service(svc, "test")
        for secret in sample_k8s_data.get("secrets", []):
            ingestor._ingest_secret(secret, "test")

        # Should have many nodes and edges
        assert len(ingestor.nodes) > 20
        assert len(ingestor.edges) > 10

        # Should detect attack edges  
        attack_edges = [e for e in ingestor.edges if e.is_attack_edge]
        assert len(attack_edges) > 0


class TestAWSIngestor:
    """Test AWS IAM ingestion logic (without Neo4j)."""

    def test_ingest_collects_nodes(self, minimal_aws_data):
        """Test that AWS ingestion creates graph nodes."""
        ingestor = AWSIngestor()

        for user in minimal_aws_data.get("users", []):
            ingestor._ingest_user(user, "123456789012")

        for group in minimal_aws_data.get("groups", []):
            ingestor._ingest_group(group, "123456789012")

        for role in minimal_aws_data.get("roles", []):
            ingestor._ingest_role(role, "123456789012")

        node_types = [n.node_type for n in ingestor.nodes]
        assert NodeType.IAM_USER in node_types
        assert NodeType.IAM_GROUP in node_types
        assert NodeType.IAM_ROLE in node_types

    def test_admin_user_detection(self, minimal_aws_data):
        """Test that admin users are flagged as critical."""
        ingestor = AWSIngestor()
        for user in minimal_aws_data.get("users", []):
            ingestor._ingest_user(user, "123456789012")

        admin = next((n for n in ingestor.nodes if n.name == "admin-user"), None)
        assert admin is not None
        assert admin.risk_level == RiskLevel.CRITICAL

    def test_dangerous_action_detection(self, minimal_aws_data):
        """Test that dangerous IAM actions are detected."""
        ingestor = AWSIngestor()
        for user in minimal_aws_data.get("users", []):
            ingestor._ingest_user(user, "123456789012")

        # dev-user has iam:PassRole and sts:AssumeRole
        dev_user = next((n for n in ingestor.nodes if n.name == "dev-user"), None)
        assert dev_user is not None
        assert dev_user.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_trust_policy_analysis(self, minimal_aws_data):
        """Test that trust relationships create assume-role edges."""
        ingestor = AWSIngestor()
        for user in minimal_aws_data.get("users", []):
            ingestor._ingest_user(user, "123456789012")
        for role in minimal_aws_data.get("roles", []):
            ingestor._ingest_role(role, "123456789012")
        for role in minimal_aws_data.get("roles", []):
            ingestor._analyze_trust_policy(role, "123456789012")

        # Should have CAN_ASSUME edges
        assume_edges = [e for e in ingestor.edges if e.relation_type == RelationType.CAN_ASSUME]
        assert len(assume_edges) > 0

    def test_user_group_linking(self, minimal_aws_data):
        """Test that user → group relationships are created."""
        ingestor = AWSIngestor()
        for user in minimal_aws_data.get("users", []):
            ingestor._ingest_user(user, "123456789012")
        for group in minimal_aws_data.get("groups", []):
            ingestor._ingest_group(group, "123456789012")
        for user in minimal_aws_data.get("users", []):
            ingestor._link_user_groups(user)

        group_edges = [e for e in ingestor.edges if e.relation_type == RelationType.IN_GROUP]
        assert len(group_edges) > 0

    def test_full_sample_data_ingestion(self, sample_aws_data):
        """Test ingestion of the full AWS sample dataset."""
        ingestor = AWSIngestor()
        for user in sample_aws_data.get("users", []):
            ingestor._ingest_user(user, "123456789012")
        for group in sample_aws_data.get("groups", []):
            ingestor._ingest_group(group, "123456789012")
        for role in sample_aws_data.get("roles", []):
            ingestor._ingest_role(role, "123456789012")
        for policy in sample_aws_data.get("policies", []):
            ingestor._ingest_policy(policy, "123456789012")
        for user in sample_aws_data.get("users", []):
            ingestor._link_user_groups(user)
        for role in sample_aws_data.get("roles", []):
            ingestor._analyze_trust_policy(role, "123456789012")

        assert len(ingestor.nodes) > 10

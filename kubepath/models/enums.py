"""Enum definitions for KubePath graph model."""

from __future__ import annotations

from enum import Enum


class NodeType(str, Enum):
    """Types of nodes in the attack graph."""
    # Kubernetes
    POD = "Pod"
    SERVICE_ACCOUNT = "ServiceAccount"
    ROLE = "Role"
    CLUSTER_ROLE = "ClusterRole"
    ROLE_BINDING = "RoleBinding"
    CLUSTER_ROLE_BINDING = "ClusterRoleBinding"
    NAMESPACE = "Namespace"
    NETWORK_POLICY = "NetworkPolicy"
    NODE = "Node"
    SECRET = "Secret"
    SERVICE = "Service"
    CONTAINER = "Container"

    # AWS IAM
    IAM_USER = "IAMUser"
    IAM_ROLE = "IAMRole"
    IAM_POLICY = "IAMPolicy"
    IAM_GROUP = "IAMGroup"
    EC2_INSTANCE = "EC2Instance"
    LAMBDA_FUNCTION = "LambdaFunction"

    # Generic
    EXTERNAL = "External"
    INTERNET = "Internet"
    CLUSTER_ADMIN = "ClusterAdmin"


class RelationType(str, Enum):
    """Types of relationships (edges) in the attack graph."""
    # Kubernetes RBAC
    BOUND_TO = "BOUND_TO"
    HAS_ROLE = "HAS_ROLE"
    RUNS_AS = "RUNS_AS"
    IN_NAMESPACE = "IN_NAMESPACE"
    GRANTS = "GRANTS"

    # Kubernetes permissions (attack-relevant)
    CAN_EXEC_INTO = "CAN_EXEC_INTO"
    CAN_GET_SECRETS = "CAN_GET_SECRETS"
    CAN_CREATE_PODS = "CAN_CREATE_PODS"
    CAN_CREATE_BINDINGS = "CAN_CREATE_BINDINGS"
    CAN_ESCALATE = "CAN_ESCALATE"
    CAN_IMPERSONATE = "CAN_IMPERSONATE"
    CAN_ACCESS = "CAN_ACCESS"
    CAN_PATCH = "CAN_PATCH"
    CAN_DELETE = "CAN_DELETE"
    CAN_LIST_SECRETS = "CAN_LIST_SECRETS"
    MOUNTS_SA_TOKEN = "MOUNTS_SA_TOKEN"

    # Network
    ALLOWS_TRAFFIC = "ALLOWS_TRAFFIC"
    EXPOSES = "EXPOSES"

    # AWS IAM
    CAN_ASSUME = "CAN_ASSUME"
    HAS_POLICY = "HAS_POLICY"
    IN_GROUP = "IN_GROUP"
    CAN_PASS_ROLE = "CAN_PASS_ROLE"
    TRUSTS = "TRUSTS"
    HAS_INSTANCE_PROFILE = "HAS_INSTANCE_PROFILE"

    # Generic attack edges
    CAN_LATERAL_MOVE = "CAN_LATERAL_MOVE"
    CAN_PRIVESC = "CAN_PRIVESC"
    CAN_CLOUD_ESCAPE = "CAN_CLOUD_ESCAPE"
    ATTACK_PATH = "ATTACK_PATH"


class RiskLevel(str, Enum):
    """Risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Risk level ordering for comparisons
RISK_LEVEL_ORDER = {
    RiskLevel.INFO: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

# Color mapping for risk levels
RISK_COLORS = {
    RiskLevel.CRITICAL: "#ff1744",
    RiskLevel.HIGH: "#ff9100",
    RiskLevel.MEDIUM: "#ffea00",
    RiskLevel.LOW: "#00e676",
    RiskLevel.INFO: "#448aff",
}

# Node type icons/shapes for frontend
NODE_SHAPES = {
    NodeType.POD: "hexagon",
    NodeType.SERVICE_ACCOUNT: "diamond",
    NodeType.ROLE: "round-rectangle",
    NodeType.CLUSTER_ROLE: "round-rectangle",
    NodeType.ROLE_BINDING: "round-triangle",
    NodeType.CLUSTER_ROLE_BINDING: "round-triangle",
    NodeType.NAMESPACE: "barrel",
    NodeType.NODE: "rectangle",
    NodeType.SECRET: "tag",
    NodeType.IAM_USER: "ellipse",
    NodeType.IAM_ROLE: "diamond",
    NodeType.IAM_POLICY: "round-rectangle",
    NodeType.IAM_GROUP: "barrel",
    NodeType.CLUSTER_ADMIN: "star",
    NodeType.INTERNET: "ellipse",
    NodeType.EXTERNAL: "ellipse",
}

# Node type colors for frontend
NODE_COLORS = {
    NodeType.POD: "#42a5f5",
    NodeType.SERVICE_ACCOUNT: "#ab47bc",
    NodeType.ROLE: "#66bb6a",
    NodeType.CLUSTER_ROLE: "#ef5350",
    NodeType.ROLE_BINDING: "#78909c",
    NodeType.CLUSTER_ROLE_BINDING: "#e57373",
    NodeType.NAMESPACE: "#5c6bc0",
    NodeType.NODE: "#8d6e63",
    NodeType.SECRET: "#ffa726",
    NodeType.SERVICE: "#26c6da",
    NodeType.IAM_USER: "#7e57c2",
    NodeType.IAM_ROLE: "#ec407a",
    NodeType.IAM_POLICY: "#26a69a",
    NodeType.IAM_GROUP: "#9ccc65",
    NodeType.CLUSTER_ADMIN: "#ff1744",
    NodeType.INTERNET: "#bdbdbd",
    NodeType.EXTERNAL: "#90a4ae",
}

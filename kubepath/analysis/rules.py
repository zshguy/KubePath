"""Attack pattern rules for KubePath.

Defines well-known privilege escalation, lateral movement, and cloud escape
patterns that the analysis engine checks for.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from kubepath.models.enums import RiskLevel


@dataclass
class AttackRule:
    """A known attack pattern."""
    rule_id: str
    name: str
    description: str
    risk_level: RiskLevel
    category: str  # "privesc", "lateral", "cloud_escape", "persistence"
    mitre_id: str = ""  # MITRE ATT&CK ID
    prerequisites: list[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""


# ── Kubernetes Privilege Escalation Rules ──────────────────────────

K8S_PRIVESC_RULES = [
    AttackRule(
        rule_id="K8S-PE-001",
        name="Pod Creation → SA Token Theft",
        description="An attacker with pod creation rights can create a pod with a privileged service account, "
                    "mount its token, and use it to escalate privileges.",
        risk_level=RiskLevel.CRITICAL,
        category="privesc",
        mitre_id="T1078.004",
        prerequisites=["create pods", "target SA with elevated privileges"],
        impact="Attacker gains the permissions of the target service account",
        remediation="Restrict pod creation to trusted users. Use admission controllers to prevent SA token mounting.",
    ),
    AttackRule(
        rule_id="K8S-PE-002",
        name="Exec into Pod → Token Access",
        description="An attacker with exec permissions can exec into any pod and steal its mounted SA token.",
        risk_level=RiskLevel.CRITICAL,
        category="privesc",
        mitre_id="T1609",
        prerequisites=["pods/exec create", "target pod with mounted SA token"],
        impact="Attacker gains the permissions of the pod's service account",
        remediation="Restrict exec permissions. Set automountServiceAccountToken: false.",
    ),
    AttackRule(
        rule_id="K8S-PE-003",
        name="Secret Read → Credential Theft",
        description="An attacker with get/list secrets can read all secrets including SA tokens, TLS certs, "
                    "database passwords, and API keys.",
        risk_level=RiskLevel.CRITICAL,
        category="privesc",
        mitre_id="T1552.007",
        prerequisites=["secrets get/list"],
        impact="Full credential access for all secrets in the namespace or cluster",
        remediation="Restrict secret access using fine-grained RBAC. Use external secret managers.",
    ),
    AttackRule(
        rule_id="K8S-PE-004",
        name="RoleBinding Creation → Self-Escalation",
        description="An attacker who can create role bindings can bind themselves to any existing role, "
                    "including cluster-admin.",
        risk_level=RiskLevel.CRITICAL,
        category="privesc",
        mitre_id="T1098",
        prerequisites=["rolebindings/clusterrolebindings create"],
        impact="Attacker can grant themselves any existing role",
        remediation="Restrict binding creation. Use the 'escalate' verb restriction.",
    ),
    AttackRule(
        rule_id="K8S-PE-005",
        name="Privileged Pod → Host Escape",
        description="A privileged pod runs without security boundaries and can access the host filesystem, "
                    "network, and processes, enabling container escape.",
        risk_level=RiskLevel.CRITICAL,
        category="privesc",
        mitre_id="T1611",
        prerequisites=["privileged: true in pod spec", "or hostPID/hostNetwork/hostPath"],
        impact="Full host access, can compromise node and all pods on it",
        remediation="Use Pod Security Standards/Policies to prevent privileged pods.",
    ),
    AttackRule(
        rule_id="K8S-PE-006",
        name="Impersonate User/Group → Identity Theft",
        description="An attacker with impersonation permissions can act as any user, group, or service account.",
        risk_level=RiskLevel.CRITICAL,
        category="privesc",
        mitre_id="T1134",
        prerequisites=["users/groups/serviceaccounts impersonate"],
        impact="Attacker can assume any identity in the cluster",
        remediation="Never grant impersonate permissions except to trusted controllers.",
    ),
    AttackRule(
        rule_id="K8S-PE-007",
        name="Node Proxy → kubelet API",
        description="Access to the node proxy subresource allows direct interaction with the kubelet API, "
                    "enabling pod listing, exec, and log access on the node.",
        risk_level=RiskLevel.CRITICAL,
        category="privesc",
        mitre_id="T1609",
        prerequisites=["nodes/proxy get"],
        impact="Full control over all pods on the target node",
        remediation="Restrict node proxy access.",
    ),
]

# ── Kubernetes Lateral Movement Rules ──────────────────────────────

K8S_LATERAL_RULES = [
    AttackRule(
        rule_id="K8S-LM-001",
        name="Pod-to-Pod via Network",
        description="Without network policies, any pod can communicate with any other pod in the cluster.",
        risk_level=RiskLevel.MEDIUM,
        category="lateral",
        mitre_id="T1210",
        prerequisites=["network access from compromised pod", "missing network policies"],
        impact="Lateral movement to any reachable pod/service",
        remediation="Implement network policies to restrict pod-to-pod traffic.",
    ),
    AttackRule(
        rule_id="K8S-LM-002",
        name="SA Token Reuse",
        description="A compromised SA token can be used from anywhere (not just the original pod) "
                    "to authenticate to the API server.",
        risk_level=RiskLevel.HIGH,
        category="lateral",
        mitre_id="T1550.001",
        prerequisites=["compromised SA token"],
        impact="API server access with the token's permissions",
        remediation="Rotate SA tokens. Use bound service account tokens with expiration.",
    ),
]

# ── AWS Privilege Escalation Rules ─────────────────────────────────

AWS_PRIVESC_RULES = [
    AttackRule(
        rule_id="AWS-PE-001",
        name="CreatePolicyVersion → Admin Escalation",
        description="An attacker with iam:CreatePolicyVersion can create a new version of an existing policy "
                    "with admin permissions and set it as default.",
        risk_level=RiskLevel.CRITICAL,
        category="privesc",
        mitre_id="T1098.003",
        prerequisites=["iam:CreatePolicyVersion"],
        impact="Full admin access by modifying a policy attached to the attacker",
        remediation="Restrict iam:CreatePolicyVersion. Use SCPs to prevent policy modification.",
    ),
    AttackRule(
        rule_id="AWS-PE-002",
        name="PassRole + Service → Admin",
        description="An attacker with iam:PassRole and the ability to create/run a service "
                    "(EC2, Lambda, ECS, etc.) can pass an admin role to the service and control it.",
        risk_level=RiskLevel.CRITICAL,
        category="privesc",
        mitre_id="T1098.003",
        prerequisites=["iam:PassRole", "ec2:RunInstances or lambda:CreateFunction"],
        impact="Execute code as the admin role",
        remediation="Restrict iam:PassRole with conditions limiting which roles can be passed.",
    ),
    AttackRule(
        rule_id="AWS-PE-003",
        name="AssumeRole Chain",
        description="An attacker can chain multiple AssumeRole calls to reach a high-privilege role "
                    "through a series of trust relationships.",
        risk_level=RiskLevel.HIGH,
        category="privesc",
        mitre_id="T1550",
        prerequisites=["sts:AssumeRole", "trust chain to admin role"],
        impact="Admin access through role chain",
        remediation="Audit and minimize role trust relationships. Use external ID conditions.",
    ),
    AttackRule(
        rule_id="AWS-PE-004",
        name="AttachPolicy → Self-Escalation",
        description="An attacker who can attach policies to users/roles/groups can attach AdministratorAccess "
                    "to their own entity.",
        risk_level=RiskLevel.CRITICAL,
        category="privesc",
        mitre_id="T1098.003",
        prerequisites=["iam:AttachUserPolicy or iam:AttachRolePolicy"],
        impact="Full admin access",
        remediation="Restrict policy attachment permissions.",
    ),
]

# ── Cloud Escape Rules ─────────────────────────────────────────────

CLOUD_ESCAPE_RULES = [
    AttackRule(
        rule_id="CE-001",
        name="K8s Node → EC2 Instance Metadata",
        description="A compromised pod with host network or node access can query the EC2 instance metadata "
                    "service (169.254.169.254) to obtain the node's IAM role credentials.",
        risk_level=RiskLevel.CRITICAL,
        category="cloud_escape",
        mitre_id="T1552.005",
        prerequisites=["host network access or node shell", "EC2 instance with IAM role"],
        impact="AWS IAM role credentials for the node",
        remediation="Use IMDSv2 (require token). Restrict pod host networking. Use IRSA for pod-level IAM.",
    ),
]

# ── All Rules Combined ─────────────────────────────────────────────

ALL_RULES = K8S_PRIVESC_RULES + K8S_LATERAL_RULES + AWS_PRIVESC_RULES + CLOUD_ESCAPE_RULES


def get_rules_by_category(category: str) -> list[AttackRule]:
    """Get rules by category."""
    return [r for r in ALL_RULES if r.category == category]


def get_all_rules() -> list[dict]:
    """Get all rules as dictionaries."""
    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "risk_level": r.risk_level.value,
            "category": r.category,
            "mitre_id": r.mitre_id,
            "prerequisites": r.prerequisites,
            "impact": r.impact,
            "remediation": r.remediation,
        }
        for r in ALL_RULES
    ]

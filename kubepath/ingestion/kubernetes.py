"""Kubernetes cluster ingestion engine.

Ingests RBAC, pods, service accounts, network policies, nodes, secrets, and
services from a Kubernetes cluster and builds the attack graph.
"""

from __future__ import annotations

import logging
from typing import Any

from kubepath.ingestion.base import BaseIngestor
from kubepath.models.graph import GraphNode, GraphEdge
from kubepath.models.enums import NodeType, RelationType, RiskLevel

logger = logging.getLogger(__name__)

# Dangerous RBAC verbs/resources that enable privilege escalation
DANGEROUS_PERMISSIONS = {
    ("pods", "create"): (RelationType.CAN_CREATE_PODS, RiskLevel.HIGH),
    ("pods/exec", "create"): (RelationType.CAN_EXEC_INTO, RiskLevel.CRITICAL),
    ("pods/exec", "get"): (RelationType.CAN_EXEC_INTO, RiskLevel.CRITICAL),
    ("secrets", "get"): (RelationType.CAN_GET_SECRETS, RiskLevel.HIGH),
    ("secrets", "list"): (RelationType.CAN_LIST_SECRETS, RiskLevel.HIGH),
    ("secrets", "watch"): (RelationType.CAN_LIST_SECRETS, RiskLevel.MEDIUM),
    ("rolebindings", "create"): (RelationType.CAN_CREATE_BINDINGS, RiskLevel.CRITICAL),
    ("clusterrolebindings", "create"): (RelationType.CAN_CREATE_BINDINGS, RiskLevel.CRITICAL),
    ("roles", "escalate"): (RelationType.CAN_ESCALATE, RiskLevel.CRITICAL),
    ("clusterroles", "escalate"): (RelationType.CAN_ESCALATE, RiskLevel.CRITICAL),
    ("serviceaccounts/token", "create"): (RelationType.CAN_ESCALATE, RiskLevel.HIGH),
    ("users", "impersonate"): (RelationType.CAN_IMPERSONATE, RiskLevel.CRITICAL),
    ("groups", "impersonate"): (RelationType.CAN_IMPERSONATE, RiskLevel.CRITICAL),
    ("serviceaccounts", "impersonate"): (RelationType.CAN_IMPERSONATE, RiskLevel.CRITICAL),
    ("pods", "delete"): (RelationType.CAN_DELETE, RiskLevel.MEDIUM),
    ("deployments", "patch"): (RelationType.CAN_PATCH, RiskLevel.HIGH),
    ("daemonsets", "patch"): (RelationType.CAN_PATCH, RiskLevel.HIGH),
    ("nodes", "proxy"): (RelationType.CAN_ACCESS, RiskLevel.CRITICAL),
    ("nodes/proxy", "get"): (RelationType.CAN_ACCESS, RiskLevel.CRITICAL),
    ("*", "*"): (RelationType.CAN_ESCALATE, RiskLevel.CRITICAL),
}


class KubernetesIngestor(BaseIngestor):
    """Ingests Kubernetes cluster data and builds the attack graph."""

    def __init__(self):
        super().__init__()
        self._node_map: dict[str, GraphNode] = {}  # key -> node

    async def ingest(self, **kwargs) -> dict[str, Any]:
        """Ingest from a live Kubernetes cluster via kubeconfig."""
        try:
            from kubernetes import client, config as k8s_config
        except ImportError:
            return {"error": "kubernetes package not installed"}

        kubeconfig = kwargs.get("kubeconfig")
        try:
            if kubeconfig:
                k8s_config.load_kube_config(config_file=kubeconfig)
            else:
                try:
                    k8s_config.load_incluster_config()
                except k8s_config.ConfigException:
                    k8s_config.load_kube_config()
        except Exception as e:
            return {"error": f"Failed to load kubeconfig: {e}"}

        v1 = client.CoreV1Api()
        rbac_v1 = client.RbacAuthorizationV1Api()
        networking_v1 = client.NetworkingV1Api()

        # Collect raw data
        data: dict[str, Any] = {}
        try:
            data["namespaces"] = [ns.to_dict() for ns in v1.list_namespace().items]
        except Exception as e:
            logger.warning("Failed to list namespaces: %s", e)
            data["namespaces"] = []

        try:
            data["pods"] = [p.to_dict() for p in v1.list_pod_for_all_namespaces().items]
        except Exception as e:
            logger.warning("Failed to list pods: %s", e)
            data["pods"] = []

        try:
            data["service_accounts"] = [sa.to_dict() for sa in v1.list_service_account_for_all_namespaces().items]
        except Exception as e:
            logger.warning("Failed to list service accounts: %s", e)
            data["service_accounts"] = []

        try:
            data["roles"] = [r.to_dict() for r in rbac_v1.list_role_for_all_namespaces().items]
        except Exception as e:
            logger.warning("Failed to list roles: %s", e)
            data["roles"] = []

        try:
            data["cluster_roles"] = [cr.to_dict() for cr in rbac_v1.list_cluster_role().items]
        except Exception as e:
            logger.warning("Failed to list cluster roles: %s", e)
            data["cluster_roles"] = []

        try:
            data["role_bindings"] = [rb.to_dict() for rb in rbac_v1.list_role_binding_for_all_namespaces().items]
        except Exception as e:
            logger.warning("Failed to list role bindings: %s", e)
            data["role_bindings"] = []

        try:
            data["cluster_role_bindings"] = [crb.to_dict() for crb in rbac_v1.list_cluster_role_binding().items]
        except Exception as e:
            logger.warning("Failed to list cluster role bindings: %s", e)
            data["cluster_role_bindings"] = []

        try:
            data["network_policies"] = [np.to_dict() for np in networking_v1.list_network_policy_for_all_namespaces().items]
        except Exception as e:
            logger.warning("Failed to list network policies: %s", e)
            data["network_policies"] = []

        try:
            data["nodes"] = [n.to_dict() for n in v1.list_node().items]
        except Exception as e:
            logger.warning("Failed to list nodes: %s", e)
            data["nodes"] = []

        try:
            data["secrets"] = [
                {"metadata": s.to_dict().get("metadata", {}), "type": s.to_dict().get("type", "")}
                for s in v1.list_secret_for_all_namespaces().items
            ]
        except Exception as e:
            logger.warning("Failed to list secrets: %s", e)
            data["secrets"] = []

        try:
            data["services"] = [svc.to_dict() for svc in v1.list_service_for_all_namespaces().items]
        except Exception as e:
            logger.warning("Failed to list services: %s", e)
            data["services"] = []

        return await self.ingest_from_data(data)

    async def ingest_from_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Ingest from pre-collected JSON data."""
        self.reset()
        self._node_map.clear()

        cluster_name = data.get("cluster_name", "cluster")

        # 1. Create cluster-admin target node
        cluster_admin = self._add_node(GraphNode(
            node_type=NodeType.CLUSTER_ADMIN,
            name="cluster-admin",
            risk_level=RiskLevel.CRITICAL,
            cluster=cluster_name,
            properties={"description": "Full cluster admin privileges"},
        ))
        self._node_map["cluster-admin"] = cluster_admin

        # 2. Ingest namespaces
        for ns_data in data.get("namespaces", []):
            self._ingest_namespace(ns_data, cluster_name)

        # 3. Ingest service accounts
        for sa_data in data.get("service_accounts", []):
            self._ingest_service_account(sa_data, cluster_name)

        # 4. Ingest pods
        for pod_data in data.get("pods", []):
            self._ingest_pod(pod_data, cluster_name)

        # 5. Ingest roles and cluster roles
        for role_data in data.get("roles", []):
            self._ingest_role(role_data, cluster_name, is_cluster_role=False)

        for cr_data in data.get("cluster_roles", []):
            self._ingest_role(cr_data, cluster_name, is_cluster_role=True)

        # 6. Ingest role bindings and cluster role bindings
        for rb_data in data.get("role_bindings", []):
            self._ingest_role_binding(rb_data, cluster_name, is_cluster_binding=False)

        for crb_data in data.get("cluster_role_bindings", []):
            self._ingest_role_binding(crb_data, cluster_name, is_cluster_binding=True)

        # 7. Ingest nodes (worker nodes)
        for node_data in data.get("nodes", []):
            self._ingest_node(node_data, cluster_name)

        # 8. Ingest secrets (metadata only)
        for secret_data in data.get("secrets", []):
            self._ingest_secret(secret_data, cluster_name)

        # 9. Ingest network policies
        for np_data in data.get("network_policies", []):
            self._ingest_network_policy(np_data, cluster_name)

        # 10. Ingest services
        for svc_data in data.get("services", []):
            self._ingest_service(svc_data, cluster_name)

        # 11. Analyze dangerous permissions and create attack edges
        self._analyze_rbac_attack_edges()

        # 12. Persist to Neo4j
        persist_stats = await self.persist()

        self.stats = {
            "namespaces": len(data.get("namespaces", [])),
            "pods": len(data.get("pods", [])),
            "service_accounts": len(data.get("service_accounts", [])),
            "roles": len(data.get("roles", [])),
            "cluster_roles": len(data.get("cluster_roles", [])),
            "role_bindings": len(data.get("role_bindings", [])),
            "cluster_role_bindings": len(data.get("cluster_role_bindings", [])),
            "network_policies": len(data.get("network_policies", [])),
            "nodes": len(data.get("nodes", [])),
            **persist_stats,
        }
        return self.stats

    # ── Internal Ingestion Methods ─────────────────────────────────

    def _get_meta(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Extract metadata from a k8s object."""
        meta = obj.get("metadata", obj)
        return {
            "name": meta.get("name", "unknown"),
            "namespace": meta.get("namespace"),
            "uid": meta.get("uid", ""),
            "labels": meta.get("labels") or {},
            "annotations": meta.get("annotations") or {},
        }

    def _make_key(self, kind: str, name: str, namespace: str | None = None) -> str:
        """Generate a unique lookup key."""
        if namespace:
            return f"{kind}:{namespace}/{name}"
        return f"{kind}:{name}"

    def _ingest_namespace(self, ns_data: dict, cluster_name: str) -> None:
        meta = self._get_meta(ns_data)
        key = self._make_key("Namespace", meta["name"])
        node = self._add_node(GraphNode(
            node_type=NodeType.NAMESPACE,
            name=meta["name"],
            risk_level=RiskLevel.INFO,
            cluster=cluster_name,
            namespace=meta["name"],
            properties={"labels": str(meta["labels"])},
        ))
        self._node_map[key] = node

    def _ingest_service_account(self, sa_data: dict, cluster_name: str) -> None:
        meta = self._get_meta(sa_data)
        ns = meta["namespace"] or "default"
        key = self._make_key("ServiceAccount", meta["name"], ns)

        automount = sa_data.get("automount_service_account_token")
        if automount is None:
            automount = True  # default is True

        risk = RiskLevel.MEDIUM if automount else RiskLevel.LOW

        node = self._add_node(GraphNode(
            node_type=NodeType.SERVICE_ACCOUNT,
            name=f"{ns}/{meta['name']}",
            risk_level=risk,
            namespace=ns,
            cluster=cluster_name,
            properties={
                "automount_token": automount,
                "short_name": meta["name"],
            },
        ))
        self._node_map[key] = node

        # Link SA to namespace
        ns_key = self._make_key("Namespace", ns)
        if ns_key in self._node_map:
            self._add_edge(GraphEdge(
                source_uid=node.uid,
                target_uid=self._node_map[ns_key].uid,
                relation_type=RelationType.IN_NAMESPACE,
            ))

    def _ingest_pod(self, pod_data: dict, cluster_name: str) -> None:
        meta = self._get_meta(pod_data)
        ns = meta["namespace"] or "default"
        key = self._make_key("Pod", meta["name"], ns)

        spec = pod_data.get("spec", {}) or {}
        sa_name = spec.get("service_account_name") or spec.get("service_account") or "default"
        host_network = spec.get("host_network", False)
        host_pid = spec.get("host_pid", False)
        host_ipc = spec.get("host_ipc", False)
        automount = spec.get("automount_service_account_token")

        # Check security context
        is_privileged = False
        can_mount_host = False
        containers = spec.get("containers", []) or []
        for container in containers:
            sc = container.get("security_context", {}) or {}
            if sc.get("privileged"):
                is_privileged = True
            vol_mounts = container.get("volume_mounts", []) or []
            for vm in vol_mounts:
                if vm.get("mount_path", "").startswith("/host"):
                    can_mount_host = True

        # Check volumes for host paths
        volumes = spec.get("volumes", []) or []
        for vol in volumes:
            if vol.get("host_path"):
                can_mount_host = True

        # Risk assessment
        risk = RiskLevel.LOW
        if is_privileged:
            risk = RiskLevel.CRITICAL
        elif host_network or host_pid or can_mount_host:
            risk = RiskLevel.HIGH
        elif host_ipc:
            risk = RiskLevel.MEDIUM

        node = self._add_node(GraphNode(
            node_type=NodeType.POD,
            name=f"{ns}/{meta['name']}",
            risk_level=risk,
            namespace=ns,
            cluster=cluster_name,
            properties={
                "service_account": sa_name,
                "host_network": host_network,
                "host_pid": host_pid,
                "host_ipc": host_ipc,
                "privileged": is_privileged,
                "host_mount": can_mount_host,
                "automount_token": automount if automount is not None else True,
                "short_name": meta["name"],
                "container_count": len(containers),
            },
        ))
        self._node_map[key] = node

        # Link Pod → ServiceAccount (RUNS_AS)
        sa_key = self._make_key("ServiceAccount", sa_name, ns)
        if sa_key in self._node_map:
            self._add_edge(GraphEdge(
                source_uid=node.uid,
                target_uid=self._node_map[sa_key].uid,
                relation_type=RelationType.RUNS_AS,
                description=f"Pod runs as SA {sa_name}",
            ))

            # If automounting, add MOUNTS_SA_TOKEN relationship
            if automount is None or automount:
                self._add_edge(GraphEdge(
                    source_uid=node.uid,
                    target_uid=self._node_map[sa_key].uid,
                    relation_type=RelationType.MOUNTS_SA_TOKEN,
                    risk_level=RiskLevel.MEDIUM,
                    description=f"Pod automounts SA token for {sa_name}",
                    is_attack_edge=True,
                ))

        # Link Pod → Namespace
        ns_key = self._make_key("Namespace", ns)
        if ns_key in self._node_map:
            self._add_edge(GraphEdge(
                source_uid=node.uid,
                target_uid=self._node_map[ns_key].uid,
                relation_type=RelationType.IN_NAMESPACE,
            ))

        # If privileged, create attack edge to node
        if is_privileged or can_mount_host:
            self._add_edge(GraphEdge(
                source_uid=node.uid,
                target_uid=self._node_map.get("cluster-admin", node).uid,
                relation_type=RelationType.CAN_PRIVESC,
                risk_level=RiskLevel.CRITICAL,
                description="Privileged pod can escape to host and escalate to cluster-admin",
                is_attack_edge=True,
            ))

    def _ingest_role(self, role_data: dict, cluster_name: str, is_cluster_role: bool) -> None:
        meta = self._get_meta(role_data)
        ns = meta["namespace"] if not is_cluster_role else None
        node_type = NodeType.CLUSTER_ROLE if is_cluster_role else NodeType.ROLE

        if is_cluster_role:
            key = self._make_key("ClusterRole", meta["name"])
        else:
            key = self._make_key("Role", meta["name"], ns)

        # Parse rules to determine risk
        rules = role_data.get("rules", []) or []
        danger_level = RiskLevel.LOW
        parsed_rules = []
        for rule in rules:
            resources = rule.get("resources", []) or []
            verbs = rule.get("verbs", []) or []
            api_groups = rule.get("api_groups", []) or [""]

            for res in resources:
                for verb in verbs:
                    parsed_rules.append(f"{res}/{verb}")
                    perm_key = (res, verb)
                    if perm_key in DANGEROUS_PERMISSIONS:
                        _, risk = DANGEROUS_PERMISSIONS[perm_key]
                        if _risk_gt(risk, danger_level):
                            danger_level = risk
                    # Check wildcard
                    if res == "*" or verb == "*":
                        danger_level = RiskLevel.CRITICAL

        # Check for cluster-admin equivalent
        is_admin = meta["name"] in ("cluster-admin", "admin", "system:masters")
        if is_admin:
            danger_level = RiskLevel.CRITICAL

        node = self._add_node(GraphNode(
            node_type=node_type,
            name=meta["name"],
            risk_level=danger_level,
            namespace=ns,
            cluster=cluster_name,
            properties={
                "rules_summary": "; ".join(parsed_rules[:20]),  # Truncate for storage
                "rule_count": len(parsed_rules),
                "is_admin": is_admin,
            },
        ))
        self._node_map[key] = node

        # If cluster-admin, link to the target node
        if is_admin and is_cluster_role:
            self._add_edge(GraphEdge(
                source_uid=node.uid,
                target_uid=self._node_map["cluster-admin"].uid,
                relation_type=RelationType.GRANTS,
                risk_level=RiskLevel.CRITICAL,
                description="Grants cluster-admin privileges",
                is_attack_edge=True,
            ))

    def _ingest_role_binding(self, rb_data: dict, cluster_name: str, is_cluster_binding: bool) -> None:
        meta = self._get_meta(rb_data)
        ns = meta["namespace"] if not is_cluster_binding else None

        if is_cluster_binding:
            key = self._make_key("ClusterRoleBinding", meta["name"])
        else:
            key = self._make_key("RoleBinding", meta["name"], ns)

        node_type = NodeType.CLUSTER_ROLE_BINDING if is_cluster_binding else NodeType.ROLE_BINDING

        # Get the role reference
        role_ref = rb_data.get("role_ref", {}) or {}
        ref_kind = role_ref.get("kind", "")
        ref_name = role_ref.get("name", "")

        node = self._add_node(GraphNode(
            node_type=node_type,
            name=meta["name"],
            risk_level=RiskLevel.INFO,
            namespace=ns,
            cluster=cluster_name,
            properties={
                "role_ref_kind": ref_kind,
                "role_ref_name": ref_name,
            },
        ))
        self._node_map[key] = node

        # Link binding → role/clusterrole
        if ref_kind == "ClusterRole":
            role_key = self._make_key("ClusterRole", ref_name)
        else:
            role_key = self._make_key("Role", ref_name, ns)

        if role_key in self._node_map:
            self._add_edge(GraphEdge(
                source_uid=node.uid,
                target_uid=self._node_map[role_key].uid,
                relation_type=RelationType.HAS_ROLE,
                description=f"Binding grants {ref_kind} {ref_name}",
            ))

        # Link subjects → binding
        subjects = rb_data.get("subjects", []) or []
        for subject in subjects:
            subj_kind = subject.get("kind", "")
            subj_name = subject.get("name", "")
            subj_ns = subject.get("namespace") or ns

            if subj_kind == "ServiceAccount":
                subj_key = self._make_key("ServiceAccount", subj_name, subj_ns)
            elif subj_kind == "User":
                subj_key = self._make_key("User", subj_name)
            elif subj_kind == "Group":
                subj_key = self._make_key("Group", subj_name)
            else:
                continue

            if subj_key in self._node_map:
                self._add_edge(GraphEdge(
                    source_uid=self._node_map[subj_key].uid,
                    target_uid=node.uid,
                    relation_type=RelationType.BOUND_TO,
                    description=f"{subj_kind} {subj_name} bound to {meta['name']}",
                ))

    def _ingest_node(self, node_data: dict, cluster_name: str) -> None:
        meta = self._get_meta(node_data)
        key = self._make_key("Node", meta["name"])

        is_master = False
        labels = meta.get("labels", {})
        if labels:
            is_master = (
                "node-role.kubernetes.io/master" in labels
                or "node-role.kubernetes.io/control-plane" in labels
            )

        risk = RiskLevel.HIGH if is_master else RiskLevel.MEDIUM

        node = self._add_node(GraphNode(
            node_type=NodeType.NODE,
            name=meta["name"],
            risk_level=risk,
            cluster=cluster_name,
            properties={
                "is_master": is_master,
                "labels": str(labels),
            },
        ))
        self._node_map[key] = node

    def _ingest_secret(self, secret_data: dict, cluster_name: str) -> None:
        meta = self._get_meta(secret_data)
        ns = meta["namespace"] or "default"
        key = self._make_key("Secret", meta["name"], ns)

        secret_type = secret_data.get("type", "Opaque")
        is_sa_token = "service-account-token" in secret_type

        risk = RiskLevel.HIGH if is_sa_token else RiskLevel.MEDIUM

        node = self._add_node(GraphNode(
            node_type=NodeType.SECRET,
            name=f"{ns}/{meta['name']}",
            risk_level=risk,
            namespace=ns,
            cluster=cluster_name,
            properties={
                "secret_type": secret_type,
                "is_sa_token": is_sa_token,
                "short_name": meta["name"],
            },
        ))
        self._node_map[key] = node

    def _ingest_network_policy(self, np_data: dict, cluster_name: str) -> None:
        meta = self._get_meta(np_data)
        ns = meta["namespace"] or "default"
        key = self._make_key("NetworkPolicy", meta["name"], ns)

        spec = np_data.get("spec", {}) or {}
        policy_types = spec.get("policy_types", []) or []

        node = self._add_node(GraphNode(
            node_type=NodeType.NETWORK_POLICY,
            name=f"{ns}/{meta['name']}",
            risk_level=RiskLevel.INFO,
            namespace=ns,
            cluster=cluster_name,
            properties={
                "policy_types": str(policy_types),
                "short_name": meta["name"],
            },
        ))
        self._node_map[key] = node

    def _ingest_service(self, svc_data: dict, cluster_name: str) -> None:
        meta = self._get_meta(svc_data)
        ns = meta["namespace"] or "default"
        key = self._make_key("Service", meta["name"], ns)

        spec = svc_data.get("spec", {}) or {}
        svc_type = spec.get("type", "ClusterIP")
        external = svc_type in ("LoadBalancer", "NodePort")

        risk = RiskLevel.MEDIUM if external else RiskLevel.LOW

        node = self._add_node(GraphNode(
            node_type=NodeType.SERVICE,
            name=f"{ns}/{meta['name']}",
            risk_level=risk,
            namespace=ns,
            cluster=cluster_name,
            properties={
                "service_type": svc_type,
                "external": external,
                "short_name": meta["name"],
            },
        ))
        self._node_map[key] = node

        # If externally accessible, create Internet → Service edge
        if external:
            internet_key = "Internet"
            if internet_key not in self._node_map:
                inet_node = self._add_node(GraphNode(
                    node_type=NodeType.INTERNET,
                    name="Internet",
                    risk_level=RiskLevel.INFO,
                    cluster=cluster_name,
                ))
                self._node_map[internet_key] = inet_node

            self._add_edge(GraphEdge(
                source_uid=self._node_map[internet_key].uid,
                target_uid=node.uid,
                relation_type=RelationType.EXPOSES,
                risk_level=RiskLevel.MEDIUM,
                description=f"Service exposed via {svc_type}",
                is_attack_edge=True,
            ))

    # ── RBAC Attack Edge Analysis ──────────────────────────────────

    def _analyze_rbac_attack_edges(self) -> None:
        """Analyze RBAC rules and create attack edges for dangerous permissions."""
        # For each role, look at parsed rules and create edges to targets
        for key, node in self._node_map.items():
            if node.node_type not in (NodeType.ROLE, NodeType.CLUSTER_ROLE):
                continue

            rules_summary = node.properties.get("rules_summary", "")
            if not rules_summary:
                continue

            # Parse each rule from the summary
            for rule_str in rules_summary.split("; "):
                parts = rule_str.strip().split("/")
                if len(parts) != 2:
                    continue
                resource, verb = parts[0], parts[1]

                perm_key = (resource, verb)
                if perm_key in DANGEROUS_PERMISSIONS:
                    rel_type, risk_level = DANGEROUS_PERMISSIONS[perm_key]

                    # Find SAs bound to this role via role bindings
                    sa_nodes = self._find_subjects_for_role(node)
                    for sa_node in sa_nodes:
                        # SA can do dangerous thing
                        self._add_edge(GraphEdge(
                            source_uid=sa_node.uid,
                            target_uid=node.uid,
                            relation_type=rel_type,
                            risk_level=risk_level,
                            description=f"Can {verb} {resource} via {node.name}",
                            is_attack_edge=True,
                        ))

                # Wildcard permissions mean full admin
                if resource == "*" and verb == "*":
                    self._add_edge(GraphEdge(
                        source_uid=node.uid,
                        target_uid=self._node_map["cluster-admin"].uid,
                        relation_type=RelationType.CAN_PRIVESC,
                        risk_level=RiskLevel.CRITICAL,
                        description="Wildcard permissions grant cluster-admin equivalent",
                        is_attack_edge=True,
                    ))

    def _find_subjects_for_role(self, role_node: GraphNode) -> list[GraphNode]:
        """Find all ServiceAccount/User subjects bound to a given role."""
        subjects = []
        for key, node in self._node_map.items():
            if node.node_type not in (NodeType.ROLE_BINDING, NodeType.CLUSTER_ROLE_BINDING):
                continue
            ref_name = node.properties.get("role_ref_name", "")
            if ref_name == role_node.name:
                # Find subjects of this binding — look for BOUND_TO edges
                for edge in self.edges:
                    if edge.target_uid == node.uid and edge.relation_type == RelationType.BOUND_TO:
                        # Find the source node
                        for k, n in self._node_map.items():
                            if n.uid == edge.source_uid:
                                subjects.append(n)
        return subjects


def _risk_gt(a: RiskLevel, b: RiskLevel) -> bool:
    """Return True if risk level a is greater than b."""
    order = {RiskLevel.INFO: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}
    return order.get(a, 0) > order.get(b, 0)

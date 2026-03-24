"""AWS IAM ingestion engine.

Ingests IAM users, roles, groups, policies, and trust relationships
from an AWS account and builds the attack graph.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import unquote

from kubepath.ingestion.base import BaseIngestor
from kubepath.models.graph import GraphNode, GraphEdge
from kubepath.models.enums import NodeType, RelationType, RiskLevel

logger = logging.getLogger(__name__)

# Dangerous AWS IAM actions
DANGEROUS_ACTIONS = {
    "iam:CreatePolicyVersion": RiskLevel.CRITICAL,
    "iam:SetDefaultPolicyVersion": RiskLevel.CRITICAL,
    "iam:PassRole": RiskLevel.CRITICAL,
    "iam:CreateLoginProfile": RiskLevel.HIGH,
    "iam:UpdateLoginProfile": RiskLevel.HIGH,
    "iam:AttachUserPolicy": RiskLevel.CRITICAL,
    "iam:AttachGroupPolicy": RiskLevel.CRITICAL,
    "iam:AttachRolePolicy": RiskLevel.CRITICAL,
    "iam:PutUserPolicy": RiskLevel.CRITICAL,
    "iam:PutGroupPolicy": RiskLevel.CRITICAL,
    "iam:PutRolePolicy": RiskLevel.CRITICAL,
    "iam:CreateAccessKey": RiskLevel.HIGH,
    "iam:AddUserToGroup": RiskLevel.HIGH,
    "sts:AssumeRole": RiskLevel.HIGH,
    "sts:AssumeRoleWithSAML": RiskLevel.HIGH,
    "sts:AssumeRoleWithWebIdentity": RiskLevel.HIGH,
    "ec2:RunInstances": RiskLevel.HIGH,
    "lambda:CreateFunction": RiskLevel.HIGH,
    "lambda:InvokeFunction": RiskLevel.MEDIUM,
    "lambda:UpdateFunctionCode": RiskLevel.HIGH,
    "lambda:CreateEventSourceMapping": RiskLevel.MEDIUM,
    "cloudformation:CreateStack": RiskLevel.HIGH,
    "datapipeline:CreatePipeline": RiskLevel.MEDIUM,
    "datapipeline:PutPipelineDefinition": RiskLevel.MEDIUM,
    "glue:CreateDevEndpoint": RiskLevel.HIGH,
    "glue:UpdateDevEndpoint": RiskLevel.HIGH,
    "ssm:SendCommand": RiskLevel.CRITICAL,
    "ssm:StartSession": RiskLevel.HIGH,
    "*": RiskLevel.CRITICAL,
}


class AWSIngestor(BaseIngestor):
    """Ingests AWS IAM data and builds the attack graph."""

    def __init__(self):
        super().__init__()
        self._node_map: dict[str, GraphNode] = {}

    async def ingest(self, **kwargs) -> dict[str, Any]:
        """Ingest from a live AWS account via boto3."""
        try:
            import boto3
        except ImportError:
            return {"error": "boto3 package not installed"}

        profile = kwargs.get("profile")
        region = kwargs.get("region", "us-east-1")

        session = boto3.Session(profile_name=profile, region_name=region)
        iam = session.client("iam")

        data: dict[str, Any] = {"account_id": "", "region": region}

        # Get account ID
        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            data["account_id"] = identity.get("Account", "")
        except Exception as e:
            logger.warning("Failed to get account ID: %s", e)

        # Users
        try:
            paginator = iam.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                users.extend(page["Users"])
            # Get inline and attached policies for each user
            for user in users:
                username = user["UserName"]
                try:
                    attached = iam.list_attached_user_policies(UserName=username)
                    user["AttachedPolicies"] = attached.get("AttachedPolicies", [])
                except Exception:
                    user["AttachedPolicies"] = []
                try:
                    inline = iam.list_user_policies(UserName=username)
                    inline_docs = []
                    for pname in inline.get("PolicyNames", []):
                        pol = iam.get_user_policy(UserName=username, PolicyName=pname)
                        inline_docs.append({"PolicyName": pname, "PolicyDocument": pol.get("PolicyDocument", {})})
                    user["InlinePolicies"] = inline_docs
                except Exception:
                    user["InlinePolicies"] = []
                try:
                    groups = iam.list_groups_for_user(UserName=username)
                    user["Groups"] = [g["GroupName"] for g in groups.get("Groups", [])]
                except Exception:
                    user["Groups"] = []
            data["users"] = users
        except Exception as e:
            logger.warning("Failed to list users: %s", e)
            data["users"] = []

        # Roles
        try:
            paginator = iam.get_paginator("list_roles")
            roles = []
            for page in paginator.paginate():
                roles.extend(page["Roles"])
            for role in roles:
                role_name = role["RoleName"]
                try:
                    attached = iam.list_attached_role_policies(RoleName=role_name)
                    role["AttachedPolicies"] = attached.get("AttachedPolicies", [])
                except Exception:
                    role["AttachedPolicies"] = []
                try:
                    inline = iam.list_role_policies(RoleName=role_name)
                    inline_docs = []
                    for pname in inline.get("PolicyNames", []):
                        pol = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
                        inline_docs.append({"PolicyName": pname, "PolicyDocument": pol.get("PolicyDocument", {})})
                    role["InlinePolicies"] = inline_docs
                except Exception:
                    role["InlinePolicies"] = []

                # Parse trust policy
                trust = role.get("AssumeRolePolicyDocument", {})
                if isinstance(trust, str):
                    trust = json.loads(unquote(trust))
                role["AssumeRolePolicyDocument"] = trust
            data["roles"] = roles
        except Exception as e:
            logger.warning("Failed to list roles: %s", e)
            data["roles"] = []

        # Groups
        try:
            paginator = iam.get_paginator("list_groups")
            groups = []
            for page in paginator.paginate():
                groups.extend(page["Groups"])
            for group in groups:
                group_name = group["GroupName"]
                try:
                    attached = iam.list_attached_group_policies(GroupName=group_name)
                    group["AttachedPolicies"] = attached.get("AttachedPolicies", [])
                except Exception:
                    group["AttachedPolicies"] = []
            data["groups"] = groups
        except Exception as e:
            logger.warning("Failed to list groups: %s", e)
            data["groups"] = []

        # Managed policies (customer-managed only for detail)
        try:
            paginator = iam.get_paginator("list_policies")
            policies = []
            for page in paginator.paginate(Scope="Local"):
                policies.extend(page["Policies"])
            for pol in policies:
                try:
                    version = iam.get_policy_version(
                        PolicyArn=pol["Arn"],
                        VersionId=pol["DefaultVersionId"]
                    )
                    doc = version.get("PolicyVersion", {}).get("Document", {})
                    if isinstance(doc, str):
                        doc = json.loads(unquote(doc))
                    pol["PolicyDocument"] = doc
                except Exception:
                    pol["PolicyDocument"] = {}
            data["policies"] = policies
        except Exception as e:
            logger.warning("Failed to list policies: %s", e)
            data["policies"] = []

        return await self.ingest_from_data(data)

    async def ingest_from_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Ingest from pre-collected JSON data."""
        self.reset()
        self._node_map.clear()

        account_id = data.get("account_id", "aws-account")

        # 1. Ingest IAM Users
        for user_data in data.get("users", []):
            self._ingest_user(user_data, account_id)

        # 2. Ingest IAM Groups
        for group_data in data.get("groups", []):
            self._ingest_group(group_data, account_id)

        # 3. Ingest IAM Roles
        for role_data in data.get("roles", []):
            self._ingest_role(role_data, account_id)

        # 4. Ingest IAM Policies
        for policy_data in data.get("policies", []):
            self._ingest_policy(policy_data, account_id)

        # 5. Create user → group relationships
        for user_data in data.get("users", []):
            self._link_user_groups(user_data)

        # 6. Analyze trust relationships for AssumeRole paths
        for role_data in data.get("roles", []):
            self._analyze_trust_policy(role_data, account_id)

        # 7. Analyze policies for dangerous permissions
        self._analyze_dangerous_permissions()

        # 8. Persist
        persist_stats = await self.persist()

        self.stats = {
            "users": len(data.get("users", [])),
            "roles": len(data.get("roles", [])),
            "groups": len(data.get("groups", [])),
            "policies": len(data.get("policies", [])),
            **persist_stats,
        }
        return self.stats

    # ── Internal Methods ───────────────────────────────────────────

    def _ingest_user(self, user_data: dict, account_id: str) -> None:
        username = user_data.get("UserName", "unknown")
        arn = user_data.get("Arn", "")
        key = f"IAMUser:{username}"

        # Analyze inline policies for risk
        risk = RiskLevel.LOW
        all_actions = self._extract_policy_actions_from_inline(user_data.get("InlinePolicies", []))
        all_actions += self._extract_attached_policy_names(user_data.get("AttachedPolicies", []))
        if self._has_admin_access(all_actions):
            risk = RiskLevel.CRITICAL
        elif self._has_dangerous_actions(all_actions):
            risk = RiskLevel.HIGH

        node = self._add_node(GraphNode(
            node_type=NodeType.IAM_USER,
            name=username,
            risk_level=risk,
            cloud_provider="aws",
            properties={
                "arn": arn,
                "account_id": account_id,
                "attached_policies": str([p.get("PolicyName", "") for p in user_data.get("AttachedPolicies", [])]),
                "group_count": len(user_data.get("Groups", [])),
            },
        ))
        self._node_map[key] = node

    def _ingest_group(self, group_data: dict, account_id: str) -> None:
        group_name = group_data.get("GroupName", "unknown")
        arn = group_data.get("Arn", "")
        key = f"IAMGroup:{group_name}"

        node = self._add_node(GraphNode(
            node_type=NodeType.IAM_GROUP,
            name=group_name,
            risk_level=RiskLevel.LOW,
            cloud_provider="aws",
            properties={
                "arn": arn,
                "account_id": account_id,
                "attached_policies": str([p.get("PolicyName", "") for p in group_data.get("AttachedPolicies", [])]),
            },
        ))
        self._node_map[key] = node

    def _ingest_role(self, role_data: dict, account_id: str) -> None:
        role_name = role_data.get("RoleName", "unknown")
        arn = role_data.get("Arn", "")
        key = f"IAMRole:{role_name}"

        # Analyze policies for risk
        risk = RiskLevel.LOW
        all_actions = self._extract_policy_actions_from_inline(role_data.get("InlinePolicies", []))
        all_actions += self._extract_attached_policy_names(role_data.get("AttachedPolicies", []))
        if self._has_admin_access(all_actions):
            risk = RiskLevel.CRITICAL
        elif self._has_dangerous_actions(all_actions):
            risk = RiskLevel.HIGH

        node = self._add_node(GraphNode(
            node_type=NodeType.IAM_ROLE,
            name=role_name,
            risk_level=risk,
            cloud_provider="aws",
            properties={
                "arn": arn,
                "account_id": account_id,
                "attached_policies": str([p.get("PolicyName", "") for p in role_data.get("AttachedPolicies", [])]),
            },
        ))
        self._node_map[key] = node

    def _ingest_policy(self, policy_data: dict, account_id: str) -> None:
        policy_name = policy_data.get("PolicyName", "unknown")
        arn = policy_data.get("Arn", "")
        key = f"IAMPolicy:{policy_name}"

        doc = policy_data.get("PolicyDocument", {})
        actions = self._extract_actions_from_document(doc)
        risk = RiskLevel.LOW
        if self._has_admin_access(actions):
            risk = RiskLevel.CRITICAL
        elif self._has_dangerous_actions(actions):
            risk = RiskLevel.HIGH

        node = self._add_node(GraphNode(
            node_type=NodeType.IAM_POLICY,
            name=policy_name,
            risk_level=risk,
            cloud_provider="aws",
            properties={
                "arn": arn,
                "account_id": account_id,
                "actions_summary": str(actions[:20]),
            },
        ))
        self._node_map[key] = node

    def _link_user_groups(self, user_data: dict) -> None:
        """Create User → Group relationships."""
        username = user_data.get("UserName", "")
        user_key = f"IAMUser:{username}"
        if user_key not in self._node_map:
            return

        for group_name in user_data.get("Groups", []):
            group_key = f"IAMGroup:{group_name}"
            if group_key in self._node_map:
                self._add_edge(GraphEdge(
                    source_uid=self._node_map[user_key].uid,
                    target_uid=self._node_map[group_key].uid,
                    relation_type=RelationType.IN_GROUP,
                    description=f"User {username} is in group {group_name}",
                ))

    def _analyze_trust_policy(self, role_data: dict, account_id: str) -> None:
        """Analyze AssumeRolePolicyDocument for trust relationships."""
        role_name = role_data.get("RoleName", "")
        role_key = f"IAMRole:{role_name}"
        if role_key not in self._node_map:
            return

        trust_doc = role_data.get("AssumeRolePolicyDocument", {})
        if isinstance(trust_doc, str):
            try:
                trust_doc = json.loads(trust_doc)
            except json.JSONDecodeError:
                return

        statements = trust_doc.get("Statement", [])
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            principal = stmt.get("Principal", {})
            if isinstance(principal, str):
                principal = {"AWS": [principal]}

            for principal_type, values in principal.items():
                if isinstance(values, str):
                    values = [values]

                for value in values:
                    self._create_trust_edge(value, role_key, role_name, account_id)

    def _create_trust_edge(self, principal: str, role_key: str, role_name: str, account_id: str) -> None:
        """Create a trust relationship edge from a principal to a role."""
        # Try to match principal to existing nodes
        if principal == "*":
            # Anyone can assume! Critical risk
            self._node_map[role_key].risk_level = RiskLevel.CRITICAL
            internet_key = "Internet"
            if internet_key not in self._node_map:
                inet_node = self._add_node(GraphNode(
                    node_type=NodeType.INTERNET,
                    name="Internet / Any AWS Principal",
                    risk_level=RiskLevel.INFO,
                    cloud_provider="aws",
                ))
                self._node_map[internet_key] = inet_node

            self._add_edge(GraphEdge(
                source_uid=self._node_map[internet_key].uid,
                target_uid=self._node_map[role_key].uid,
                relation_type=RelationType.CAN_ASSUME,
                risk_level=RiskLevel.CRITICAL,
                description=f"Any principal can assume role {role_name}",
                is_attack_edge=True,
            ))
            return

        # Check if it's an ARN matching a known user or role
        if ":user/" in principal:
            username = principal.split(":user/")[-1]
            user_key = f"IAMUser:{username}"
            if user_key in self._node_map:
                self._add_edge(GraphEdge(
                    source_uid=self._node_map[user_key].uid,
                    target_uid=self._node_map[role_key].uid,
                    relation_type=RelationType.CAN_ASSUME,
                    risk_level=RiskLevel.HIGH,
                    description=f"User {username} can assume role {role_name}",
                    is_attack_edge=True,
                ))

        elif ":role/" in principal:
            other_role = principal.split(":role/")[-1]
            other_key = f"IAMRole:{other_role}"
            if other_key in self._node_map:
                self._add_edge(GraphEdge(
                    source_uid=self._node_map[other_key].uid,
                    target_uid=self._node_map[role_key].uid,
                    relation_type=RelationType.CAN_ASSUME,
                    risk_level=RiskLevel.HIGH,
                    description=f"Role {other_role} can assume role {role_name}",
                    is_attack_edge=True,
                ))

        elif ":root" in principal:
            # Entire account can assume
            self._add_edge(GraphEdge(
                source_uid=self._node_map.get(f"IAMUser:{account_id}", GraphNode(
                    node_type=NodeType.EXTERNAL,
                    name=f"Account {principal.split(':')[4] if ':' in principal else account_id}",
                    cloud_provider="aws",
                )).uid if f"IAMUser:{account_id}" in self._node_map else self._add_node(GraphNode(
                    node_type=NodeType.EXTERNAL,
                    name=f"Account Root ({principal})",
                    risk_level=RiskLevel.MEDIUM,
                    cloud_provider="aws",
                )).uid,
                target_uid=self._node_map[role_key].uid,
                relation_type=RelationType.TRUSTS,
                risk_level=RiskLevel.MEDIUM,
                description=f"Account root trusted to assume {role_name}",
                is_attack_edge=True,
            ))

    def _analyze_dangerous_permissions(self) -> None:
        """Scan all IAM entities for dangerous permissions."""
        for key, node in self._node_map.items():
            if node.node_type not in (NodeType.IAM_USER, NodeType.IAM_ROLE):
                continue

            actions_str = node.properties.get("actions_summary", "")
            if "*" in actions_str or "AdministratorAccess" in node.properties.get("attached_policies", ""):
                # Admin access — mark as critical
                if node.risk_level != RiskLevel.CRITICAL:
                    node.risk_level = RiskLevel.CRITICAL

    # ── Policy Parsing Helpers ─────────────────────────────────────

    def _extract_actions_from_document(self, doc: dict) -> list[str]:
        """Extract all allowed actions from a policy document."""
        actions = []
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            stmt_actions = stmt.get("Action", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]
            actions.extend(stmt_actions)
        return actions

    def _extract_policy_actions_from_inline(self, inline_policies: list) -> list[str]:
        """Extract actions from inline policy documents."""
        actions = []
        for pol in inline_policies:
            doc = pol.get("PolicyDocument", {})
            actions.extend(self._extract_actions_from_document(doc))
        return actions

    def _extract_attached_policy_names(self, attached: list) -> list[str]:
        """Extract attached policy names (for admin check)."""
        return [p.get("PolicyName", "") for p in attached]

    def _has_admin_access(self, actions_or_names: list[str]) -> bool:
        """Check if the entity has admin-level access."""
        for item in actions_or_names:
            if item in ("*", "*:*", "AdministratorAccess"):
                return True
            if item == "iam:*" or item == "s3:*":
                continue  # Not full admin by themselves
        return False

    def _has_dangerous_actions(self, actions: list[str]) -> bool:
        """Check if any action is in the dangerous list."""
        for action in actions:
            if action in DANGEROUS_ACTIONS:
                return True
            # Check wildcard matching
            if "*" in action:
                return True
        return False

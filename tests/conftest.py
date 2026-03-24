"""Shared test fixtures for KubePath."""

import json
import pytest
from pathlib import Path


@pytest.fixture
def sample_k8s_data():
    """Load the sample Kubernetes cluster data."""
    data_path = Path(__file__).parent.parent / "sample_data" / "k8s_cluster.json"
    with open(data_path) as f:
        return json.load(f)


@pytest.fixture
def sample_aws_data():
    """Load the sample AWS IAM data."""
    data_path = Path(__file__).parent.parent / "sample_data" / "aws_iam.json"
    with open(data_path) as f:
        return json.load(f)


@pytest.fixture
def minimal_k8s_data():
    """Minimal K8s data for unit tests."""
    return {
        "cluster_name": "test-cluster",
        "namespaces": [
            {"metadata": {"name": "default", "uid": "ns-1"}},
            {"metadata": {"name": "production", "uid": "ns-2"}},
        ],
        "service_accounts": [
            {"metadata": {"name": "default", "namespace": "default", "uid": "sa-1"}, "automount_service_account_token": True},
            {"metadata": {"name": "priv-sa", "namespace": "production", "uid": "sa-2"}, "automount_service_account_token": True},
        ],
        "pods": [
            {
                "metadata": {"name": "web-pod", "namespace": "production", "uid": "pod-1"},
                "spec": {
                    "service_account_name": "priv-sa",
                    "automount_service_account_token": True,
                    "containers": [{"name": "web", "security_context": {"privileged": True}}],
                    "host_network": False, "host_pid": False, "host_ipc": False,
                },
            },
        ],
        "roles": [],
        "cluster_roles": [
            {
                "metadata": {"name": "cluster-admin", "uid": "cr-1"},
                "rules": [{"resources": ["*"], "verbs": ["*"], "api_groups": ["*"]}],
            },
        ],
        "role_bindings": [],
        "cluster_role_bindings": [
            {
                "metadata": {"name": "priv-sa-admin", "uid": "crb-1"},
                "role_ref": {"kind": "ClusterRole", "name": "cluster-admin"},
                "subjects": [{"kind": "ServiceAccount", "name": "priv-sa", "namespace": "production"}],
            },
        ],
        "nodes": [],
        "secrets": [],
        "services": [],
        "network_policies": [],
    }


@pytest.fixture
def minimal_aws_data():
    """Minimal AWS IAM data for unit tests."""
    return {
        "account_id": "123456789012",
        "region": "us-east-1",
        "users": [
            {
                "UserName": "admin-user",
                "Arn": "arn:aws:iam::123456789012:user/admin-user",
                "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}],
                "InlinePolicies": [],
                "Groups": ["admins"],
            },
            {
                "UserName": "dev-user",
                "Arn": "arn:aws:iam::123456789012:user/dev-user",
                "AttachedPolicies": [],
                "InlinePolicies": [
                    {
                        "PolicyName": "dev-policy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": ["sts:AssumeRole", "iam:PassRole"], "Resource": "*"}
                            ],
                        },
                    }
                ],
                "Groups": [],
            },
        ],
        "groups": [
            {
                "GroupName": "admins",
                "Arn": "arn:aws:iam::123456789012:group/admins",
                "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}],
            },
        ],
        "roles": [
            {
                "RoleName": "admin-role",
                "Arn": "arn:aws:iam::123456789012:role/admin-role",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:user/dev-user"}, "Action": "sts:AssumeRole"}
                    ],
                },
                "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}],
                "InlinePolicies": [],
            },
        ],
        "policies": [],
    }

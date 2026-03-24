"""Tests for KubePath analysis engine."""

from kubepath.analysis.rules import ALL_RULES, get_all_rules, get_rules_by_category
from kubepath.models.enums import RiskLevel


class TestAttackRules:
    """Test attack rules definitions."""

    def test_all_rules_exist(self):
        assert len(ALL_RULES) > 10

    def test_rules_have_required_fields(self):
        for rule in ALL_RULES:
            assert rule.rule_id, f"Rule missing ID"
            assert rule.name, f"Rule {rule.rule_id} missing name"
            assert rule.description, f"Rule {rule.rule_id} missing description"
            assert rule.risk_level, f"Rule {rule.rule_id} missing risk level"
            assert rule.category, f"Rule {rule.rule_id} missing category"

    def test_get_rules_by_category(self):
        privesc = get_rules_by_category("privesc")
        assert len(privesc) > 5

        lateral = get_rules_by_category("lateral")
        assert len(lateral) > 0

        cloud_escape = get_rules_by_category("cloud_escape")
        assert len(cloud_escape) > 0

    def test_get_all_rules_as_dicts(self):
        rules = get_all_rules()
        assert len(rules) == len(ALL_RULES)
        for r in rules:
            assert "rule_id" in r
            assert "name" in r
            assert "risk_level" in r

    def test_k8s_privesc_rules(self):
        privesc = get_rules_by_category("privesc")
        # Should include critical rules
        rule_ids = [r.rule_id for r in privesc]
        assert "K8S-PE-001" in rule_ids  # Pod creation
        assert "K8S-PE-002" in rule_ids  # Exec
        assert "K8S-PE-005" in rule_ids  # Privileged pod

    def test_aws_privesc_rules(self):
        rules = get_all_rules()
        aws_rules = [r for r in rules if r["rule_id"].startswith("AWS-")]
        assert len(aws_rules) > 0

    def test_mitre_ids(self):
        """All rules should have MITRE ATT&CK IDs."""
        for rule in ALL_RULES:
            assert rule.mitre_id, f"Rule {rule.rule_id} missing MITRE ID"

    def test_critical_rules_exist(self):
        """There should be multiple CRITICAL risk rules."""
        critical = [r for r in ALL_RULES if r.risk_level == RiskLevel.CRITICAL]
        assert len(critical) >= 5

"""Tests for deterministic rule-based CSP risk assessment."""

import unittest

from csp_scanner.assess import assess, parse_csp, score_to_level


def rule_ids(assessment):
    return [f.rule_id for f in assessment.findings]


class ParseTests(unittest.TestCase):
    def test_parse_basic(self):
        directives = parse_csp("default-src 'self'; script-src 'self' cdn.test")
        self.assertEqual(directives["default-src"], ["'self'"])
        self.assertEqual(directives["script-src"], ["'self'", "cdn.test"])

    def test_first_directive_occurrence_wins(self):
        directives = parse_csp("script-src 'self'; script-src *")
        self.assertEqual(directives["script-src"], ["'self'"])


class AssessTests(unittest.TestCase):
    def test_missing_csp_is_critical(self):
        result = assess(None, None)
        self.assertIn("CSP-001", rule_ids(result))
        self.assertEqual(result.level, "critical")

    def test_report_only_without_enforced(self):
        result = assess(None, "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.assertIn("CSP-002", rule_ids(result))
        self.assertNotIn("CSP-001", rule_ids(result))

    def test_unsafe_inline_and_eval(self):
        result = assess("script-src 'unsafe-inline' 'unsafe-eval' 'self'")
        ids = rule_ids(result)
        self.assertIn("CSP-010", ids)
        self.assertIn("CSP-011", ids)

    def test_unsafe_inline_with_nonce_downgraded(self):
        result = assess("script-src 'unsafe-inline' 'nonce-abc123'")
        finding = next(f for f in result.findings if f.rule_id == "CSP-010")
        self.assertEqual(finding.severity, "medium")

    def test_wildcard_script_src_is_critical_finding(self):
        result = assess("script-src *")
        finding = next(f for f in result.findings if f.rule_id == "CSP-020")
        self.assertEqual(finding.severity, "critical")

    def test_broad_default_src_scheme_only(self):
        result = assess("default-src https:")
        self.assertIn("CSP-021", rule_ids(result))

    def test_data_in_script_src(self):
        result = assess("script-src data:")
        self.assertIn("CSP-030", rule_ids(result))

    def test_data_in_object_src_via_default_fallback(self):
        result = assess("default-src data:")
        ids = rule_ids(result)
        self.assertIn("CSP-030", ids)

    def test_missing_hardening_directives(self):
        result = assess("script-src 'self'")
        ids = rule_ids(result)
        self.assertIn("CSP-040", ids)  # object-src
        self.assertIn("CSP-041", ids)  # base-uri
        self.assertIn("CSP-042", ids)  # frame-ancestors

    def test_strong_policy_is_low_risk(self):
        result = assess(
            "default-src 'none'; script-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
        self.assertEqual(result.findings, [])
        self.assertEqual(result.score, 0)
        self.assertEqual(result.level, "low")

    def test_deterministic(self):
        policy = "default-src *; script-src 'unsafe-inline' data:"
        first = assess(policy)
        second = assess(policy)
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_findings_have_required_fields(self):
        result = assess(None)
        for finding in result.findings:
            data = finding.to_dict()
            for key in ("rule_id", "severity", "directive", "explanation",
                        "score", "remediation"):
                self.assertTrue(data[key] not in (None, ""), key)

    def test_score_to_level_thresholds(self):
        self.assertEqual(score_to_level(0), "low")
        self.assertEqual(score_to_level(15), "medium")
        self.assertEqual(score_to_level(35), "high")
        self.assertEqual(score_to_level(60), "critical")


if __name__ == "__main__":
    unittest.main()

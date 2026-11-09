import json
import unittest

from scripts.trufflehog_scan import evaluate_findings, finding_fingerprint


def make_finding(raw="test-only synthetic candidate", verified=False):
    return {
        "DetectorName": "Wit",
        "Verified": verified,
        "Raw": raw,
        "SourceMetadata": {
            "Data": {
                "Git": {
                    "commit": "0123456789abcdef",
                    "file": "src/security/report_test.go",
                    "line": 33,
                }
            }
        },
    }


class TruffleHogScanTests(unittest.TestCase):
    def setUp(self):
        self.finding = make_finding()
        self.fingerprint = finding_fingerprint(self.finding)
        self.allowlist = {
            self.fingerprint: {
                "fingerprint": self.fingerprint,
                "detector": "Wit",
                "commit": "0123456789abcdef",
                "file": "src/security/report_test.go",
                "line": 33,
                "reason": "Synthetic fixture used only by the test.",
            }
        }

    def test_accepts_exact_reviewed_unverified_finding(self):
        rejected, matched = evaluate_findings([json.dumps(self.finding)], self.allowlist)
        self.assertEqual(rejected, [])
        self.assertEqual(matched, {self.fingerprint})

    def test_rejects_changed_candidate(self):
        candidate = "different test-only candidate"
        changed = make_finding(raw=candidate)
        rejected, matched = evaluate_findings([json.dumps(changed)], self.allowlist)
        self.assertEqual(len(rejected), 1)
        self.assertNotIn(candidate, json.dumps(rejected))
        self.assertEqual(matched, set())

    def test_never_allows_verified_findings(self):
        candidate = "verified synthetic candidate"
        verified = make_finding(raw=candidate, verified=True)
        rejected, matched = evaluate_findings([json.dumps(verified)], self.allowlist)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["reason"], "verified finding")
        self.assertNotIn(candidate, json.dumps(rejected))
        self.assertEqual(matched, set())

    def test_rejects_invalid_json(self):
        rejected, matched = evaluate_findings(["not-json"], self.allowlist)
        self.assertEqual(rejected[0]["reason"], "invalid finding record")
        self.assertEqual(matched, set())


if __name__ == "__main__":
    unittest.main()

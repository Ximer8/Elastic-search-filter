import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from modules.base import ScanTarget
from modules.trufflehog_s3 import TruffleHogS3Module


class TruffleHogS3ModuleTests(unittest.TestCase):
    def test_verified_secret_is_redacted_and_reportable(self):
        payload = {
            "DetectorName": "AWS",
            "DecoderName": "PLAIN",
            "Verified": True,
            "Raw": "AKIAEXAMPLESECRET123456",
            "Redacted": "AKIA...3456",
            "SourceMetadata": {"Data": {"S3": {"bucket": "company-prod", "key": "config/.env"}}},
        }
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(payload) + "\n", stderr="")

        with patch("modules.trufflehog_s3.shutil.which", return_value="/usr/bin/trufflehog"):
            with patch("modules.trufflehog_s3.subprocess.run", return_value=completed) as run:
                results = list(TruffleHogS3Module().scan(
                    ScanTarget(raw="s3://company-prod", host="company-prod"),
                    timeout=3,
                    sample_size=100,
                ))

        result = results[0].to_dict()
        finding = result["trufflehog_findings"][0]
        self.assertEqual(result["severity_score"], 95)
        self.assertEqual(result["trufflehog_verified_count"], 1)
        self.assertEqual(finding["object_key"], "config/.env")
        self.assertEqual(finding["redacted"], "AKIA...3456")
        self.assertNotIn("AKIAEXAMPLESECRET123456", json.dumps(result))
        self.assertEqual(run.call_args.args[0], [
            "/usr/bin/trufflehog", "s3", "--bucket=company-prod", "--json", "--no-update",
        ])

    def test_missing_binary_skips_scan(self):
        with patch("modules.trufflehog_s3.shutil.which", return_value=None):
            results = list(TruffleHogS3Module().scan(
                ScanTarget(raw="s3://company-prod", host="company-prod"),
                timeout=3,
                sample_size=100,
            ))
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()

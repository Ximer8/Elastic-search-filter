import json
import os
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from modules.base import ScanTarget
from modules.trufflehog_s3 import TruffleHogS3Module


class TruffleHogS3ModuleTests(unittest.TestCase):
    def setUp(self):
        TruffleHogS3Module._warnings = set()
        TruffleHogS3Module._cached_binary = None
        TruffleHogS3Module._prompted_for_binary = False

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

    def test_prompted_binary_path_is_used_when_not_in_path(self):
        payload = {
            "DetectorName": "AWS",
            "DecoderName": "PLAIN",
            "Verified": False,
            "Raw": "secret-value-example",
            "SourceMetadata": {"Data": {"S3": {"bucket": "company-prod", "key": "config/app.env"}}},
        }
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(payload) + "\n", stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            binary = os.path.join(tmpdir, "trufflehog")
            with open(binary, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\n")
            os.chmod(binary, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            with patch("modules.trufflehog_s3.shutil.which", return_value=None):
                with patch("modules.trufflehog_s3.sys.stdin.isatty", return_value=True):
                    with patch("builtins.input", return_value=binary):
                        with patch("modules.trufflehog_s3.subprocess.run", return_value=completed) as run:
                            results = list(TruffleHogS3Module().scan(
                                ScanTarget(raw="s3://company-prod", host="company-prod"),
                                timeout=3,
                                sample_size=100,
                            ))

        self.assertEqual(len(results), 1)
        self.assertEqual(run.call_args.args[0], [
            binary, "s3", "--bucket=company-prod", "--json", "--no-update",
        ])


if __name__ == "__main__":
    unittest.main()

import os
import tempfile
import unittest
from unittest.mock import patch

from modules.reporter import is_confirmed_critical_s3, is_reportable_critical_s3, write_critical_reports


def confirmed_s3_result():
    return {
        "module": "s3_bucket_impact",
        "url": "https://company-prod-backups.s3.amazonaws.com",
        "host": "company-prod-backups",
        "bucket": "company-prod-backups",
        "region": "us-east-1",
        "accessible": True,
        "severity_score": 95,
        "notification_priority": "urgent",
        "detected_rules": [
            "public_bucket_listing",
            "public_object_read",
            "database_backups",
            "secrets",
        ],
        "listed_objects": 2,
        "public_read_checked": 2,
        "status_codes": {
            "bucket_head": 200,
            "list_objects": 200,
        },
        "sample_data": {
            "database_backups": {
                "matched": ["db/prod-backup.sql"],
            },
            "secrets": {
                "matched": ["config/.env"],
            },
        },
        "checked_objects": [
            {
                "key": "db/prod-backup.sql",
                "status": 200,
                "public_read": True,
                "content_length": "123",
            },
            {
                "key": "config/.env",
                "status": 200,
                "public_read": True,
                "content_length": "45",
            },
        ],
        "evidence": [
            "bucket_head:http_200",
            "list_objects:http_200",
            "public_read_objects:2",
        ],
        "environment": "production",
        "environment_confidence": 80,
    }


def confirmed_elasticsearch_result():
    return {
        "module": "elasticsearch",
        "url": "http://10.0.0.10:9200",
        "host": "10.0.0.10",
        "port": 9200,
        "scheme": "http",
        "accessible": True,
        "cluster_name": "prod-search",
        "version": "8.12.0",
        "indices_count": 14,
        "severity_score": 54,
        "detected_rules": ["credentials", "pii", "production", "backups"],
        "sample_data": {
            "credentials": {
                "category": "CRITICAL",
                "description": "API keys, secrets, tokens",
                "matched": ["api_key", "token"],
                "severity": 10,
            },
            "pii": {
                "category": "CRITICAL",
                "description": "Personal Identifiable Information",
                "matched": ["email", "phone"],
                "severity": 9,
            },
            "production": {
                "category": "HIGH",
                "description": "Production environment",
                "matched": ["customer", "account_id"],
                "severity": 7,
            },
            "backups": {
                "category": "MEDIUM",
                "description": "Backup/dump files",
                "matched": ["backup"],
                "severity": 7,
            },
        },
        "environment": "production",
        "environment_confidence": 80,
        "environment_signals": ["cluster:prod"],
        "response_time": 0.12,
    }


def confirmed_laravel_result(score=75):
    return {
        "module": "laravel_debug",
        "url": "https://prod.example.com",
        "host": "prod.example.com",
        "port": 443,
        "scheme": "https",
        "accessible": True,
        "severity_score": score,
        "notification_priority": "urgent" if score >= 70 else "high",
        "detected_rules": ["laravel_debug", "server_error_debug", "stack_trace", "env_secrets"],
        "sample_data": {
            "laravel_debug": {
                "category": "CRITICAL",
                "description": "Laravel debug/exception page is exposed",
                "matched": ["laravel", "ignition"],
                "severity": 10,
            },
            "stack_trace": {
                "category": "HIGH",
                "description": "Stack trace or trace frames are exposed",
                "matched": ["stack trace", "trace"],
                "severity": 8,
            },
            "env_secrets": {
                "category": "CRITICAL",
                "description": "Environment variables or secrets appear in debug output",
                "matched": ["app_key", "db_password"],
                "severity": 10,
            },
        },
        "environment": "production",
        "environment_confidence": 90,
        "environment_signals": ["content:APP_ENV=production"],
        "false_positive_confidence": 95,
        "evidence": [
            "not_found_probe:http_500",
            "laravel:laravel",
            "debug:ignition",
            "debug:stack trace",
            "secret:app_key",
        ],
        "checked_paths": [
            "https://prod.example.com/",
            "https://prod.example.com/_scanner_laravel_debug_probe_404",
        ],
        "status_codes": {
            "root": 200,
            "not_found_probe": 500,
        },
        "owner": {
            "company": "Example",
            "contacts": ["security@example.com"],
            "confidence": 80,
            "sources": ["security.txt"],
        },
        "response_time": 0.33,
    }


def confirmed_trufflehog_result():
    return {
        "module": "trufflehog_s3",
        "url": "s3://company-prod",
        "host": "company-prod",
        "bucket": "company-prod",
        "accessible": True,
        "severity_score": 95,
        "notification_priority": "urgent",
        "detected_rules": ["verified_secret"],
        "trufflehog_verified_count": 1,
        "trufflehog_unverified_count": 0,
        "trufflehog_findings": [{
            "detector": "AWS",
            "decoder": "PLAIN",
            "verified": True,
            "bucket": "company-prod",
            "object_key": "config/.env",
            "redacted": "AKIA...3456",
            "fingerprint": "0123456789abcdef",
        }],
        "evidence": ["trufflehog:findings=1", "trufflehog:verified=1"],
    }


class ReporterTests(unittest.TestCase):
    def test_verified_trufflehog_s3_writes_redacted_report_package(self):
        result = confirmed_trufflehog_result()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("modules.reporter._find_screenshot_browser", return_value=""):
                report_dirs = write_critical_reports([result], tmpdir)

            self.assertEqual(len(report_dirs), 1)
            report_dir = report_dirs[0]
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_screenshot.png")))
            with open(os.path.join(report_dir, "report.md"), "r", encoding="utf-8") as f:
                report = f.read()
            self.assertIn("Confirmed TruffleHog Secret Exposure", report)
            self.assertIn("Verified=true", report)
            self.assertIn("AKIA...3456", report)
            self.assertIn("Raw secrets are intentionally excluded", report)

    def test_confirmed_critical_s3_writes_report_package(self):
        result = confirmed_s3_result()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("modules.reporter.write_proof_screenshot", return_value=True):
                report_dirs = write_critical_reports([result], tmpdir)

            self.assertEqual(len(report_dirs), 1)
            report_dir = report_dirs[0]
            self.assertEqual(os.path.basename(os.path.dirname(report_dir)), "critical")
            self.assertTrue(os.path.exists(os.path.join(report_dir, "report.md")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "evidence.json")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_snapshot.html")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_snapshot.svg")))

            with open(os.path.join(report_dir, "report.md"), "r", encoding="utf-8") as f:
                report = f.read()

            self.assertIn("Confirmed Critical S3 Exposure", report)
            self.assertIn("False Positive Controls", report)
            self.assertIn("Anonymous ListObjectsV2 returned HTTP 200", report)
            self.assertIn("proof_screenshot.png", report)
            self.assertIn("proof_screenshot_impact.png", report)
            self.assertIn("proof_screenshot_validation.png", report)
            self.assertIn("Anonymous Validation", report)
            self.assertIn("curl -sS", report)
            self.assertIn("Content-Length", report)

    def test_reporter_skips_unconfirmed_s3_result(self):
        result = confirmed_s3_result()
        result["severity_score"] = 40
        result["detected_rules"] = ["listing_blocked", "business_context_in_name"]
        result["listed_objects"] = 0
        result["status_codes"] = {"bucket_head": 403, "list_objects": 403}
        result["checked_objects"] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            report_dirs = write_critical_reports([result], tmpdir)

            self.assertFalse(is_confirmed_critical_s3(result))
            self.assertFalse(is_reportable_critical_s3(result))
            self.assertEqual(report_dirs, [])
            self.assertEqual(os.listdir(tmpdir), [])

    def test_confirmed_s3_non_production_is_reported_by_severity(self):
        result = confirmed_s3_result()
        result["environment"] = "test"

        with tempfile.TemporaryDirectory() as tmpdir:
            report_dirs = write_critical_reports([result], tmpdir)

            self.assertTrue(is_confirmed_critical_s3(result))
            self.assertFalse(is_reportable_critical_s3(result))
            self.assertEqual(len(report_dirs), 1)
            self.assertEqual(os.path.basename(os.path.dirname(report_dirs[0])), "critical")

    def test_screenshot_png_is_generated_for_reportable_finding(self):
        result = confirmed_s3_result()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("modules.reporter._find_screenshot_browser", return_value=""):
                report_dirs = write_critical_reports([result], tmpdir)

            screenshot = os.path.join(report_dirs[0], "proof_screenshot.png")
            self.assertTrue(os.path.exists(screenshot))
            self.assertGreater(os.path.getsize(screenshot), 0)
            self.assertTrue(os.path.exists(os.path.join(report_dirs[0], "proof_screenshot_impact.png")))
            self.assertTrue(os.path.exists(os.path.join(report_dirs[0], "proof_screenshot_validation.png")))

    def test_confirmed_critical_elasticsearch_writes_report_package(self):
        result = confirmed_elasticsearch_result()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("modules.reporter._find_screenshot_browser", return_value=""):
                report_dirs = write_critical_reports([result], tmpdir)

            self.assertEqual(len(report_dirs), 1)
            report_dir = report_dirs[0]
            self.assertEqual(os.path.basename(os.path.dirname(report_dir)), "critical")
            self.assertTrue(os.path.exists(os.path.join(report_dir, "report.md")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "evidence.json")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_snapshot.html")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_snapshot.svg")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_screenshot.png")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_screenshot_impact.png")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_screenshot_validation.png")))

            with open(os.path.join(report_dir, "report.md"), "r", encoding="utf-8") as f:
                report = f.read()

            self.assertIn("Confirmed Critical Elasticsearch Exposure", report)
            self.assertIn("False Positive Controls", report)
            self.assertIn("Critical detection rules matched", report)
            self.assertIn("Anonymous Validation", report)
            self.assertIn("curl -sS", report)

    def test_reporter_skips_unconfirmed_elasticsearch_result(self):
        result = confirmed_elasticsearch_result()
        result["cluster_name"] = ""
        result["version"] = ""
        result["indices_count"] = 0

        with tempfile.TemporaryDirectory() as tmpdir:
            report_dirs = write_critical_reports([result], tmpdir)

            self.assertEqual(report_dirs, [])
            self.assertEqual(os.listdir(tmpdir), [])

    def test_reporter_skips_non_critical_elasticsearch_result(self):
        result = confirmed_elasticsearch_result()
        result["severity_score"] = 5

        with tempfile.TemporaryDirectory() as tmpdir:
            report_dirs = write_critical_reports([result], tmpdir)

            self.assertEqual(report_dirs, [])
            self.assertEqual(os.listdir(tmpdir), [])

    def test_high_elasticsearch_report_is_separated_without_png_screenshot(self):
        result = confirmed_elasticsearch_result()
        result["severity_score"] = 35

        with tempfile.TemporaryDirectory() as tmpdir:
            report_dirs = write_critical_reports([result], tmpdir)

            self.assertEqual(len(report_dirs), 1)
            self.assertEqual(os.path.basename(os.path.dirname(report_dirs[0])), "high")
            self.assertTrue(os.path.exists(os.path.join(report_dirs[0], "report.md")))
            self.assertFalse(os.path.exists(os.path.join(report_dirs[0], "proof_screenshot.png")))

    def test_confirmed_critical_laravel_writes_report_package_with_screenshot(self):
        result = confirmed_laravel_result()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("modules.reporter._find_screenshot_browser", return_value=""):
                report_dirs = write_critical_reports([result], tmpdir)

            self.assertEqual(len(report_dirs), 1)
            report_dir = report_dirs[0]
            self.assertEqual(os.path.basename(os.path.dirname(report_dir)), "critical")
            self.assertTrue(os.path.exists(os.path.join(report_dir, "report.md")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "evidence.json")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_snapshot.html")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_snapshot.svg")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_screenshot.png")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_screenshot_impact.png")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "proof_screenshot_validation.png")))

            with open(os.path.join(report_dir, "report.md"), "r", encoding="utf-8") as f:
                report = f.read()

            self.assertIn("Confirmed Laravel Debug Exposure", report)
            self.assertIn("False Positive Controls", report)
            self.assertIn("APP_DEBUG=false", report)
            self.assertIn("Anonymous Validation", report)
            self.assertIn("curl -i", report)

    def test_medium_laravel_report_is_separated_without_png_screenshot(self):
        result = confirmed_laravel_result(score=25)
        result["detected_rules"] = ["laravel_debug", "server_error_debug"]
        result["sample_data"] = {
            "laravel_debug": result["sample_data"]["laravel_debug"],
            "server_error_debug": {
                "category": "HIGH",
                "description": "Debug page is reachable on server error response",
                "matched": ["500"],
                "severity": 8,
            },
        }
        result["evidence"] = [
            "not_found_probe:http_500",
            "laravel:laravel",
            "debug:ignition",
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            report_dirs = write_critical_reports([result], tmpdir)

            self.assertEqual(len(report_dirs), 1)
            self.assertEqual(os.path.basename(os.path.dirname(report_dirs[0])), "medium")
            self.assertTrue(os.path.exists(os.path.join(report_dirs[0], "report.md")))
            self.assertFalse(os.path.exists(os.path.join(report_dirs[0], "proof_screenshot.png")))

    def test_reporter_skips_unconfirmed_laravel_debug_result(self):
        result = confirmed_laravel_result()
        result["evidence"] = ["not_found_probe:http_500", "debug:stack trace"]

        with tempfile.TemporaryDirectory() as tmpdir:
            report_dirs = write_critical_reports([result], tmpdir)

            self.assertEqual(report_dirs, [])
            self.assertEqual(os.listdir(tmpdir), [])


if __name__ == "__main__":
    unittest.main()

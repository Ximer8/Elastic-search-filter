import unittest
from unittest.mock import patch

from modules.base import ScanTarget
from modules.s3_bucket_impact import S3BucketImpactModule


class FakeResponse:
    def __init__(self, status_code, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = text.encode("utf-8")


class S3BucketImpactTests(unittest.TestCase):
    def test_bucket_name_extraction_formats(self):
        module = S3BucketImpactModule()
        samples = {
            "company-prod-backups": "company-prod-backups",
            "s3://company-prod-backups": "company-prod-backups",
            "company-prod-backups.s3.amazonaws.com": "company-prod-backups",
            "https://company-prod-backups.s3.amazonaws.com": "company-prod-backups",
            "https://s3.amazonaws.com/company-prod-backups": "company-prod-backups",
            "https://company-prod-backups.s3.us-east-1.amazonaws.com": "company-prod-backups",
        }

        for raw, expected in samples.items():
            with self.subTest(raw=raw):
                target = ScanTarget(raw=raw, host=raw)
                self.assertEqual(module._bucket_from_target(target), expected)

    def test_public_listing_generates_impact_report_without_downloading_objects(self):
        module = S3BucketImpactModule()
        target = ScanTarget(raw="company-prod-backups", host="company-prod-backups")
        listing_xml = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>company-prod-backups</Name>
  <Contents><Key>db/prod-backup.sql</Key></Contents>
  <Contents><Key>config/.env</Key></Contents>
</ListBucketResult>"""

        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url))
            if method == "HEAD" and url == "https://company-prod-backups.s3.amazonaws.com":
                return FakeResponse(200, {"x-amz-bucket-region": "us-east-1"})
            if method == "GET" and "list-type=2" in url:
                return FakeResponse(200, {"Content-Type": "application/xml"}, listing_xml)
            if method == "HEAD" and url.endswith("/db/prod-backup.sql"):
                return FakeResponse(200, {"Content-Length": "123"})
            if method == "HEAD" and url.endswith("/config/.env"):
                return FakeResponse(200, {"Content-Length": "45"})
            return FakeResponse(404)

        with patch("modules.s3_bucket_impact.requests.request", side_effect=fake_request):
            results = list(module.scan(target, timeout=1, sample_size=100))

        self.assertEqual(len(results), 1)
        result = results[0].to_dict()
        self.assertEqual(result["bucket"], "company-prod-backups")
        self.assertEqual(result["region"], "us-east-1")
        self.assertTrue(result["public_listing"])
        self.assertIn("public_bucket_listing", result["detected_rules"])
        self.assertIn("public_object_read", result["detected_rules"])
        self.assertIn("database_backups", result["detected_rules"])
        self.assertIn("secrets", result["detected_rules"])
        self.assertIn("Recommended Remediation", result["security_report"])
        self.assertNotIn(("GET", "https://company-prod-backups.s3.amazonaws.com/db/prod-backup.sql"), calls)


if __name__ == "__main__":
    unittest.main()

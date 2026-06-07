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

    def test_regular_domain_is_not_treated_as_bucket(self):
        module = S3BucketImpactModule()
        samples = [
            ScanTarget(raw="gamerask.com", host="gamerask.com"),
            ScanTarget(raw="assets3.example.com", host="assets3.example.com"),
            ScanTarget(raw="https://assets3.example.com/logo.png", host="assets3.example.com", scheme="https"),
        ]

        for target in samples:
            with self.subTest(raw=target.raw):
                with patch("modules.s3_bucket_impact.requests.request") as request:
                    results = list(module.scan(target, timeout=1, sample_size=100))

                self.assertEqual(results, [])
                request.assert_not_called()

    def test_supports_target_only_for_bucket_like_values(self):
        module = S3BucketImpactModule()

        self.assertFalse(module.supports_target(
            ScanTarget(raw="https://example.com/app.js", host="example.com", scheme="https")
        ))
        self.assertTrue(module.supports_target(
            ScanTarget(raw="https://company-prod.s3.amazonaws.com", host="company-prod.s3.amazonaws.com", scheme="https")
        ))
        self.assertTrue(module.supports_target(
            ScanTarget(raw="s3://company-prod", host="company-prod", scheme="s3")
        ))

    def test_regional_endpoint_is_preserved_before_canonical_fallback(self):
        module = S3BucketImpactModule()
        target = ScanTarget(
            raw="https://company-prod-backups.s3.ap-south-1.amazonaws.com",
            host="company-prod-backups.s3.ap-south-1.amazonaws.com",
            scheme="https",
            url="https://company-prod-backups.s3.ap-south-1.amazonaws.com",
        )
        listing_xml = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>company-prod-backups</Name>
  <Contents><Key>config/.env</Key></Contents>
</ListBucketResult>"""

        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url))
            if url.startswith("https://company-prod-backups.s3.ap-south-1.amazonaws.com"):
                if method == "HEAD" and url == "https://company-prod-backups.s3.ap-south-1.amazonaws.com":
                    return FakeResponse(200, {"x-amz-bucket-region": "ap-south-1"})
                if method == "GET" and "list-type=2" in url:
                    return FakeResponse(200, {"Content-Type": "application/xml"}, listing_xml)
                if method == "HEAD" and url.endswith("/config/.env"):
                    return FakeResponse(200, {"Content-Length": "128"})
            if url.startswith("https://company-prod-backups.s3.amazonaws.com"):
                return FakeResponse(404, {"Server": "AmazonS3"}, "<Error><Code>NoSuchBucket</Code></Error>")
            return FakeResponse(404)

        with patch("modules.s3_bucket_impact.requests.request", side_effect=fake_request):
            results = list(module.scan(target, timeout=1, sample_size=100))

        self.assertEqual(len(results), 1)
        result = results[0].to_dict()
        self.assertEqual(result["url"], "https://company-prod-backups.s3.ap-south-1.amazonaws.com")
        self.assertEqual(result["endpoint_source"], "original")
        self.assertIn("public_bucket_listing", result["detected_rules"])
        self.assertNotIn(("HEAD", "https://company-prod-backups.s3.amazonaws.com"), calls)

    def test_path_style_regional_endpoint_uses_bucket_path_for_listing_and_objects(self):
        module = S3BucketImpactModule()
        target = ScanTarget(
            raw="https://s3.ap-south-1.amazonaws.com/company-prod-backups",
            host="s3.ap-south-1.amazonaws.com",
            scheme="https",
            url="https://s3.ap-south-1.amazonaws.com/company-prod-backups",
        )
        listing_xml = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>company-prod-backups</Name>
  <Contents><Key>db/prod-backup.sql</Key></Contents>
</ListBucketResult>"""

        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url))
            if method == "HEAD" and url == "https://s3.ap-south-1.amazonaws.com/company-prod-backups":
                return FakeResponse(200, {"x-amz-bucket-region": "ap-south-1"})
            if method == "GET" and url.startswith("https://s3.ap-south-1.amazonaws.com/company-prod-backups?"):
                return FakeResponse(200, {"Content-Type": "application/xml"}, listing_xml)
            if method == "HEAD" and url == "https://s3.ap-south-1.amazonaws.com/company-prod-backups/db/prod-backup.sql":
                return FakeResponse(200, {"Content-Length": "256"})
            return FakeResponse(404)

        with patch("modules.s3_bucket_impact.requests.request", side_effect=fake_request):
            results = list(module.scan(target, timeout=1, sample_size=100))

        self.assertEqual(len(results), 1)
        self.assertIn(("GET", "https://s3.ap-south-1.amazonaws.com/company-prod-backups?list-type=2&max-keys=100"), calls)
        self.assertIn(
            ("HEAD", "https://s3.ap-south-1.amazonaws.com/company-prod-backups/db/prod-backup.sql"),
            calls,
        )

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

    def test_public_listing_is_checked_when_bucket_head_returns_s3_404(self):
        module = S3BucketImpactModule()
        target = ScanTarget(raw="company-prod-backups", host="company-prod-backups")
        listing_xml = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>company-prod-backups</Name>
  <Contents><Key>db/prod-backup.sql</Key></Contents>
</ListBucketResult>"""

        def fake_request(method, url, **kwargs):
            if method == "HEAD" and url == "https://company-prod-backups.s3.amazonaws.com":
                return FakeResponse(404, {"Server": "AmazonS3"})
            if method == "GET" and "list-type=2" in url:
                return FakeResponse(200, {"Content-Type": "application/xml", "x-amz-bucket-region": "us-east-1"}, listing_xml)
            if method == "HEAD" and url.endswith("/db/prod-backup.sql"):
                return FakeResponse(200, {"Content-Length": "123"})
            return FakeResponse(404)

        with patch("modules.s3_bucket_impact.requests.request", side_effect=fake_request):
            results = list(module.scan(target, timeout=1, sample_size=100))

        self.assertEqual(len(results), 1)
        result = results[0].to_dict()
        self.assertEqual(result["status_codes"]["bucket_head"], 404)
        self.assertEqual(result["status_codes"]["list_objects"], 200)
        self.assertTrue(result["public_listing"])
        self.assertIn("public_bucket_listing", result["detected_rules"])

    def test_static_assets_do_not_become_critical_without_sensitive_names(self):
        module = S3BucketImpactModule()
        target = ScanTarget(raw="static-assets", host="static-assets")
        listing_xml = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>static-assets</Name>
  <Contents><Key>app.js</Key></Contents>
  <Contents><Key>style.css</Key></Contents>
  <Contents><Key>logo.png</Key></Contents>
  <Contents><Key>photo.jpg</Key></Contents>
  <Contents><Key>font.woff2</Key></Contents>
</ListBucketResult>"""

        def fake_request(method, url, **kwargs):
            if method == "HEAD" and url == "https://static-assets.s3.amazonaws.com":
                return FakeResponse(404, {"Server": "AmazonS3"})
            if method == "GET" and "list-type=2" in url:
                return FakeResponse(200, {"Content-Type": "application/xml"}, listing_xml)
            if method == "HEAD":
                return FakeResponse(200, {"Content-Length": "12345"})
            return FakeResponse(404)

        with patch("modules.s3_bucket_impact.requests.request", side_effect=fake_request):
            results = list(module.scan(target, timeout=1, sample_size=100))

        self.assertEqual(len(results), 1)
        result = results[0].to_dict()
        self.assertLess(result["severity_score"], 50)
        self.assertNotIn("source_code", result["detected_rules"])

    def test_business_context_name_only_is_returned_for_review(self):
        module = S3BucketImpactModule()
        target = ScanTarget(raw="company-prod-assets", host="company-prod-assets")

        def fake_request(method, url, **kwargs):
            if method == "HEAD" and url == "https://company-prod-assets.s3.amazonaws.com":
                return FakeResponse(404, {"Server": "AmazonS3"})
            if method == "GET" and "list-type=2" in url:
                return FakeResponse(404, {"Content-Type": "application/xml"})
            return FakeResponse(404)

        with patch("modules.s3_bucket_impact.requests.request", side_effect=fake_request):
            results = list(module.scan(target, timeout=1, sample_size=100))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].detected_rules, ["business_context_in_name"])


if __name__ == "__main__":
    unittest.main()

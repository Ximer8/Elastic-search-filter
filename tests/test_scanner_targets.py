import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

from scanner import format_available_modules, load_cached_results, load_targets, write_cache_manifest


class ScannerTargetLoadingTests(unittest.TestCase):
    def test_url_lines_are_not_duplicated_by_generic_loader(self):
        content = "\n".join(
            [
                "http://10.0.0.1:9200",
                "https://10.0.0.2:9200",
                "http://10.0.0.3:9200",
            ]
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            targets = load_targets(tmp_path)
        finally:
            os.unlink(tmp_path)

        self.assertEqual(len(targets), 3)
        self.assertEqual(sorted((target.host, target.port) for target in targets), [
            ("10.0.0.1", 9200),
            ("10.0.0.2", 9200),
            ("10.0.0.3", 9200),
        ])

    def test_single_column_url_header_is_not_loaded_as_bucket_target(self):
        content = "\n".join(
            [
                "url",
                "https://example.com/app.js",
                "https://demo-bucket.s3.amazonaws.com",
                "https://s3.amazonaws.com/path-style-bucket",
                "s3://another-demo-bucket",
            ]
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            targets = load_targets(tmp_path)
        finally:
            os.unlink(tmp_path)

        self.assertEqual([target.raw for target in targets], [
            "example.com",
            "https://demo-bucket.s3.amazonaws.com",
            "https://s3.amazonaws.com/path-style-bucket",
            "s3://another-demo-bucket",
        ])

    def test_available_modules_output_is_readable(self):
        output = format_available_modules()

        self.assertIn("Available modules:", output)
        self.assertIn("elasticsearch", output)
        self.assertIn("laravel_debug", output)
        self.assertIn("s3_bucket_impact", output)
        self.assertIn("trufflehog_s3", output)
        self.assertIn("--modules all", output)

    def test_list_modules_does_not_require_input_file(self):
        result = subprocess.run(
            [sys.executable, "scanner.py", "--list-modules"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Available modules:", result.stdout)
        self.assertIn("elasticsearch", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_scan_cache_matches_same_input_and_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "targets.txt")
            out_json = os.path.join(tmpdir, "scan_results.json")
            with open(input_path, "w", encoding="utf-8") as f:
                f.write("example-bucket\n")
            with open(out_json, "w", encoding="utf-8") as f:
                f.write('[{"module": "s3_bucket_impact", "severity_score": 30}]')

            args = SimpleNamespace(
                input=input_path,
                out_json=out_json,
                delimiter=",",
                sample_size=500,
            )
            write_cache_manifest(args, ["s3_bucket_impact"])

            cached = load_cached_results(args, ["s3_bucket_impact"])
            self.assertEqual(len(cached), 1)

            with open(input_path, "a", encoding="utf-8") as f:
                f.write("changed\n")

            self.assertIsNone(load_cached_results(args, ["s3_bucket_impact"]))


if __name__ == "__main__":
    unittest.main()

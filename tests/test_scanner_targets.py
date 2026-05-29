import os
import tempfile
import unittest

from scanner import load_targets


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


if __name__ == "__main__":
    unittest.main()

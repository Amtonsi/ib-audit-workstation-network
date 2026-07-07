import unittest

from ib_audit.version_expression import matches_version_expression


class VersionExpressionTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(matches_version_expression("12.3.1", "12.3.1"))

    def test_exact_mismatch(self):
        self.assertFalse(matches_version_expression("12.3.2", "12.3.1"))

    def test_range_with_less_than(self):
        self.assertTrue(matches_version_expression("12.3.0", "before 12.4"))
        self.assertFalse(matches_version_expression("12.5", "before 12.4"))

    def test_range_with_or_more(self):
        self.assertTrue(matches_version_expression("12.5.1", "12.3 and later"))
        self.assertFalse(matches_version_expression("12.2.9", "12.3 and later"))

    def test_from_to_range_inclusive_false(self):
        self.assertFalse(matches_version_expression("12.03.1", "from 12.03.0001 to 12.03.1"))

    def test_from_to_range_inclusive_true(self):
        self.assertTrue(matches_version_expression("12.03.0001", "from 12.03.0001 to 12.3.1 including"))
        self.assertTrue(matches_version_expression("12.3.1", "from 12.03.0001 to 12.3.1 including"))

    def test_hyphen_range(self):
        self.assertTrue(matches_version_expression("12.3.2", "12.1-12.4"))

    def test_comparator_match(self):
        self.assertTrue(matches_version_expression("12.3.1", ">=12.3.1"))
        self.assertTrue(matches_version_expression("12.3.0", "< 12.3.1"))

    def test_ambiguous_without_version_info(self):
        self.assertIsNone(matches_version_expression("12.3.1", "may have this vulnerability"))
        self.assertIsNone(matches_version_expression("12.3.1", "no data"))

    def test_multiple_alternatives(self):
        self.assertTrue(matches_version_expression("12.3.1", "12.3.0, 12.3.1, 12.3.2"))
        self.assertTrue(matches_version_expression("12.3.1", "<=12.5"))


if __name__ == "__main__":
    unittest.main()

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.category_catalog import WINAUDIT_CATEGORIES, category_for_name


class CategoryCatalogTests(unittest.TestCase):
    def test_catalog_contains_the_agreed_46_categories(self):
        self.assertEqual(46, len(WINAUDIT_CATEGORIES))
        self.assertEqual("System Overview", WINAUDIT_CATEGORIES[0].name)
        self.assertEqual("OLE DB Drivers", WINAUDIT_CATEGORIES[-1].name)

    def test_unknown_category_is_preserved(self):
        category = category_for_name("Vendor Extension")
        self.assertEqual("Vendor Extension", category.name)
        self.assertEqual("unknown", category.object_type)

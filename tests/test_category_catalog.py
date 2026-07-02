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

    def test_russian_winaudit_hardware_sections_map_to_vulnerability_candidates(self):
        self.assertEqual("device", category_for_name("Диспетчер устройств").object_type)
        self.assertEqual("bios", category_for_name("Версия BIOS").object_type)
        self.assertEqual("physical_disk", category_for_name("Жесткие диски").object_type)
        self.assertEqual("network_adapter", category_for_name("Network Adapters").object_type)

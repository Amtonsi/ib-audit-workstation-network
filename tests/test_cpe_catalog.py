import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.cpe_catalog import CpeCatalog
from ib_audit.identity import InventoryIdentityResolver
from ib_audit.models import InventoryObject
from ib_audit.vulnerability_database import VulnerabilityDatabaseBuilder


class CpeCatalogTests(unittest.TestCase):
    def test_resolves_sql_server_family_from_winaudit_component_name(self):
        with self._catalog(
            [
                ("SQL-1", "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*", "Microsoft SQL Server"),
                ("OFFICE-1", "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*", "Microsoft Office"),
            ]
        ) as db_path:
            identity = InventoryIdentityResolver().resolve(
                InventoryObject(
                    "s",
                    "Installed Software",
                    "software",
                    "SQL Server 2012 Common Files",
                    {"Vendor": "Microsoft", "Version": "11.1.3000.0"},
                    "fixture",
                ),
                [],
            )

            resolution = CpeCatalog(db_path).resolve(identity)

        self.assertEqual("resolved", resolution.status)
        self.assertEqual("sql_server", resolution.candidates[0].cpe.product)

    def test_resolves_acronis_backup_without_global_backup_alias(self):
        with self._catalog(
            [
                ("ACRONIS-1", "cpe:2.3:a:acronis:cyber_backup:*:*:*:*:*:*:*:*", "Acronis Cyber Backup"),
                ("OTHER-1", "cpe:2.3:a:other:backup:*:*:*:*:*:*:*:*", "Other Backup"),
            ]
        ) as db_path:
            identity = InventoryIdentityResolver().resolve(
                InventoryObject(
                    "s",
                    "Installed Software",
                    "software",
                    "Acronis Backup 11.7 Agent Core",
                    {"Vendor": "Acronis", "Version": "11.7.50058"},
                    "fixture",
                ),
                [],
            )

            resolution = CpeCatalog(db_path).resolve(identity)

        self.assertEqual("resolved", resolution.status)
        self.assertEqual("acronis", resolution.candidates[0].cpe.vendor)
        self.assertEqual("cyber_backup", resolution.candidates[0].cpe.product)

    def test_resolves_processor_model_to_hardware_cpe(self):
        with self._catalog(
            [
                ("CPU-1", "cpe:2.3:h:intel:xeon:e5620:*:*:*:*:*:*:*", "Intel Xeon E5620"),
            ]
        ) as db_path:
            identity = InventoryIdentityResolver().resolve(
                InventoryObject(
                    "p",
                    "Processors",
                    "processor",
                    "Intel(R) Xeon(R) CPU E5620 @ 2.40GHz",
                    {"Manufacturer": "Intel(R) Corporation"},
                    "fixture",
                ),
                [],
            )

            resolution = CpeCatalog(db_path).resolve(identity)

        self.assertEqual("resolved", resolution.status)
        self.assertEqual("h", resolution.candidates[0].cpe.part)
        self.assertEqual("e5620", resolution.candidates[0].cpe.version)

    def test_marks_close_candidates_ambiguous(self):
        with self._catalog(
            [
                ("BACKUP-1", "cpe:2.3:a:example:backup:*:*:*:*:*:*:*:*", "Example Backup"),
                ("BACKUP-2", "cpe:2.3:a:example:backup_agent:*:*:*:*:*:*:*:*", "Example Backup Agent"),
            ]
        ) as db_path:
            identity = InventoryIdentityResolver().resolve(
                InventoryObject(
                    "s",
                    "Installed Software",
                    "software",
                    "Example Backup",
                    {"Vendor": "Example", "Version": "1.0"},
                    "fixture",
                ),
                [],
            )

            resolution = CpeCatalog(db_path).resolve(identity)

        self.assertEqual("ambiguous", resolution.status)
        self.assertGreaterEqual(len(resolution.candidates), 2)

    def _catalog(self, cpes: list[tuple[str, str, str]]):
        return _CatalogFixture(cpes)


class _CatalogFixture:
    def __init__(self, cpes: list[tuple[str, str, str]]):
        self.cpes = cpes
        self.temp = tempfile.TemporaryDirectory()

    def __enter__(self) -> Path:
        root = Path(self.temp.__enter__())
        self.db_path = root / "vulnerability_sources.db"
        VulnerabilityDatabaseBuilder(root / "snapshots", self.db_path).build_database([])
        con = sqlite3.connect(self.db_path)
        try:
            con.execute(
                "insert into cpe_catalog_generations(id,created_at,status) values(1,'2099-01-01T00:00:00+00:00','active')"
            )
            con.execute(
                """
                insert into source_sync_state(source,active_generation_id,sha256,size_bytes,updated_at)
                values('nvd-cpe-catalog',1,'fixture',0,'2099-01-01T00:00:00+00:00')
                """
            )
            for cpe_name_id, cpe_name, title in self.cpes:
                parts = cpe_name.split(":")
                con.execute(
                    """
                    insert into nvd_cpe_names(
                        generation_id,cpe_name_id,cpe_name,part,vendor,product,version,
                        update_value,deprecated,title
                    ) values(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        1,
                        cpe_name_id,
                        cpe_name,
                        parts[2],
                        parts[3],
                        parts[4],
                        parts[5],
                        parts[6],
                        0,
                        title,
                    ),
                )
            con.commit()
        finally:
            con.close()
        return self.db_path

    def __exit__(self, exc_type, exc, tb):
        return self.temp.__exit__(exc_type, exc, tb)

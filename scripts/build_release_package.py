from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def build_release_zip(
    output_zip: str | Path,
    app_dir: str | Path = "outputs/dist-full-audit/IBAuditWorkstation",
    vulnerability_dir: str | Path = "outputs/vulnerability-database",
    user_guide: str | Path = "outputs/release/IBAuditWorkstation_UserGuide_RU.pdf",
    license_file: str | Path = "LICENSE",
) -> Path:
    output = Path(output_zip)
    output.parent.mkdir(parents=True, exist_ok=True)
    app = Path(app_dir)
    vuln = Path(vulnerability_dir)
    guide = Path(user_guide)
    license_path = Path(license_file)
    app_executable = app / "IBAuditWorkstation.exe" if app.is_dir() else app
    if app_executable.suffix.lower() != ".exe":
        app_executable = app / "IBAuditWorkstation.exe"
    required = [app_executable, vuln / "vulnerability_sources.db", guide, license_path]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError("Missing release inputs: " + ", ".join(missing))

    manifest: dict[str, object] = {
        "built_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "files": [],
    }

    def add_file(zip_handle: zipfile.ZipFile, path: Path, arcname: str) -> None:
        zip_handle.write(path, arcname)
        manifest["files"].append({"path": arcname, "sha256": sha256(path), "size": path.stat().st_size})

    if output.exists():
        output.unlink()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        if app.is_dir():
            for path in iter_files(app):
                add_file(archive, path, f"IBAuditWorkstation/{path.relative_to(app).as_posix()}")
        else:
            add_file(archive, app_executable, f"IBAuditWorkstation/{app_executable.name}")
        for path in iter_files(vuln):
            add_file(archive, path, f"vulnerability-database/{path.relative_to(vuln).as_posix()}")
        add_file(archive, guide, f"docs/{guide.name}")
        add_file(archive, license_path, "LICENSE")
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        archive.writestr("release-manifest.json", manifest_bytes)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a local licensed ZIP with EXE, vulnerability DB, snapshots, and guide.")
    parser.add_argument("--output", default="outputs/release/IBAuditWorkstation_release.zip")
    parser.add_argument("--app-dir", default="outputs/dist-full-audit/IBAuditWorkstation")
    parser.add_argument("--vulnerability-dir", default="outputs/vulnerability-database")
    parser.add_argument("--user-guide", default="outputs/release/IBAuditWorkstation_UserGuide_RU.pdf")
    parser.add_argument("--license-file", default="LICENSE")
    parser.add_argument(
        "--i-confirm-redistribution-rights",
        action="store_true",
        help="Confirm that every bundled third-party component may be redistributed in this product.",
    )
    args = parser.parse_args()
    if not args.i_confirm_redistribution_rights:
        parser.error(
            "Refusing to package an EXE without --i-confirm-redistribution-rights. "
            "Public releases should use the source archive instead."
        )
    path = build_release_zip(args.output, args.app_dir, args.vulnerability_dir, args.user_guide, args.license_file)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

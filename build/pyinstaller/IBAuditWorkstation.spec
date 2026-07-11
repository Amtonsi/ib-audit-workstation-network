# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import zipfile

from PyInstaller.utils.hooks import collect_data_files


SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent.parent
TOOLS_ROOT = PROJECT_ROOT / 'tools'
TOOL_BUNDLE_ROOT = PROJECT_ROOT / 'build' / 'tool-bundles'


def build_tool_bundle(tool_name):
    source_dir = TOOLS_ROOT / tool_name
    if not source_dir.exists():
        raise FileNotFoundError(source_dir)
    target = TOOL_BUNDLE_ROOT / f'{tool_name}.zip'
    TOOL_BUNDLE_ROOT.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.rglob('*')):
            if path.is_file():
                archive.write(path, path.relative_to(source_dir).as_posix())
    return str(target)


def optional_tool_tree(tool_name):
    source_dir = TOOLS_ROOT / tool_name
    if not source_dir.exists():
        return []
    return [(str(source_dir), f'tools/{tool_name}')]


a = Analysis(
    ['..\\..\\run_app.py'],
    pathex=['src'],
    binaries=[],
    datas=[
        ('../../src/ib_audit/rulepacks/*.json', 'ib_audit/rulepacks'),
        (build_tool_bundle('nmap'), 'tools-bundles'),
        (build_tool_bundle('wireshark'), 'tools-bundles'),
        *optional_tool_tree('npcap'),
        *collect_data_files('customtkinter'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='IBAuditWorkstation',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

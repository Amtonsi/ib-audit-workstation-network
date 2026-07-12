# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import fnmatch
import os
import zipfile

from PyInstaller.utils.hooks import collect_data_files


SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent.parent
TOOLS_ROOT = PROJECT_ROOT / 'tools'
TOOL_BUNDLE_ROOT = PROJECT_ROOT / 'build' / 'tool-bundles'
BUILD_PROFILE = os.environ.get('IB_AUDIT_BUILD_PROFILE', 'community').strip().casefold()
LICENSE_ACK = os.environ.get('IB_AUDIT_LICENSE_ACK', '')
LICENSE_ACK_VALUE = 'I_HAVE_DISTRIBUTION_RIGHTS'
INCLUDE_NPCAP_OEM = os.environ.get('IB_AUDIT_INCLUDE_NPCAP_OEM', '0') == '1'

if BUILD_PROFILE not in {'community', 'licensed-local'}:
    raise RuntimeError(f'Unsupported IB_AUDIT_BUILD_PROFILE: {BUILD_PROFILE}')
if BUILD_PROFILE == 'licensed-local' and LICENSE_ACK != LICENSE_ACK_VALUE:
    raise RuntimeError(
        'Licensed tool bundling requires IB_AUDIT_LICENSE_ACK=I_HAVE_DISTRIBUTION_RIGHTS. '
        'Use scripts/build_licensed_exe.ps1 instead of invoking PyInstaller directly.'
    )


def build_tool_bundle(tool_name, exclude_patterns=()):
    source_dir = TOOLS_ROOT / tool_name
    if not source_dir.exists():
        raise FileNotFoundError(source_dir)
    target = TOOL_BUNDLE_ROOT / f'{tool_name}.zip'
    TOOL_BUNDLE_ROOT.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.rglob('*')):
            if path.is_file():
                relative_name = path.relative_to(source_dir).as_posix()
                if any(fnmatch.fnmatch(relative_name.casefold(), pattern.casefold()) for pattern in exclude_patterns):
                    continue
                archive.write(path, path.relative_to(source_dir).as_posix())
    return str(target)


def optional_tool_tree(tool_name):
    source_dir = TOOLS_ROOT / tool_name
    if not source_dir.exists():
        return []
    return [(str(source_dir), f'tools/{tool_name}')]


def licensed_tool_datas():
    if BUILD_PROFILE != 'licensed-local':
        return []
    result = [
        (build_tool_bundle('nmap', exclude_patterns=('npcap*.exe', '**/npcap*.exe')), 'tools-bundles'),
        (build_tool_bundle('wireshark'), 'tools-bundles'),
    ]
    if INCLUDE_NPCAP_OEM:
        npcap_tree = optional_tool_tree('npcap-oem')
        if not npcap_tree:
            raise FileNotFoundError(TOOLS_ROOT / 'npcap-oem')
        result.extend(npcap_tree)
    return result


a = Analysis(
    ['..\\..\\run_app.py'],
    pathex=['src'],
    binaries=[],
    datas=[
        ('../../src/ib_audit/rulepacks/*.json', 'ib_audit/rulepacks'),
        *licensed_tool_datas(),
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

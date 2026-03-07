# -*- mode: python ; coding: utf-8 -*-
# HashGuard CLI PyInstaller spec file
# Builds: hashguard.exe (command-line interface)

from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ['../src/hashguard/cli.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('../src/hashguard/data/signatures.json', '.'),
        ('../assets/branding', 'assets/branding'),
        ('../yara_rules', 'yara_rules'),
        ('../src/hashguard/data', 'data'),
    ],
    hiddenimports=[
        'hashguard.scanner',
        'hashguard.config',
        'hashguard.logger',
        'hashguard.reports',
        'hashguard.pe_analyzer',
        'hashguard.yara_scanner',
        'hashguard.threat_intel',
        'hashguard.risk_scorer',
        'hashguard.string_extractor',
        'pefile',
        'yara',
    ] + collect_submodules('hashguard'),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='hashguard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    manifest='hashguard.manifest',
    icon='../assets/branding/hashguard.ico',
    version='version_info_cli.py',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name='hashguard',
)

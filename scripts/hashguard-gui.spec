# -*- mode: python ; coding: utf-8 -*-
# HashGuard GUI PyInstaller spec file
# Builds: hashguard-gui.exe (graphical user interface)

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

# Collect tkinterdnd2 platform-specific libraries
_dnd_datas = collect_data_files('tkinterdnd2')

a = Analysis(
    ['../src/hashguard/gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('../src/hashguard/data/signatures.json', '.'),
        ('../assets/branding', 'assets/branding'),
        ('../yara_rules', 'yara_rules'),
        ('../src/hashguard/data', 'data'),
    ] + _dnd_datas,
    hiddenimports=[
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinterdnd2',
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
    ] + collect_submodules('hashguard') + collect_submodules('tkinterdnd2'),
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
    name='hashguard-gui',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Don't show console window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    manifest='hashguard.manifest',
    icon='../assets/branding/hashguard.ico',
    version='version_info_gui.py',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name='hashguard-gui',
)

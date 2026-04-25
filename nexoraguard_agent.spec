# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for NexoraGuard Remote Agent
# Build: pyinstaller nexoraguard_agent.spec --clean

import os
block_cipher = None

a = Analysis(
    ['backend/agent_client.py'],
    pathex=[os.path.abspath('backend')],
    binaries=[],
    datas=[
        ('logo.ico', '.'),
    ],
    hiddenimports=[
        'pystray._win32',
        'PIL._tkinter_finder',
        'PIL.Image',
        'PIL.ImageDraw',
        'winreg',
        'tkinter',
        'tkinter.font',
        'psutil',
        'requests',
        'urllib3',
        'charset_normalizer',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib','numpy','pandas','scipy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='NexoraGuard-Agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No console window — runs silently
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='logo.ico',
    version_file=None,
    uac_admin=False,        # Does NOT need admin — runs as normal user
)

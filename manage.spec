# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['manage.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['manager'],  # 如果有其他模块需要导入，添加到这里
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
    [],
    exclude_binaries=True,
    name='WebXplore',  # 修改为你的可执行文件名
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='WebXplore',  # 确保与 EXE 名称一致
)
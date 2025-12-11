from cx_Freeze import setup, Executable
import sys
from pathlib import Path
import os

sys.setrecursionlimit(8000)

exe = Executable(
    script="ClusterCommand.py",
    base="Console",
)

site_packages = next(p for p in sys.path if 'site-packages' in p)
setup(
    name="ClusterCommand",
    version="__VERSION__",
    description="ClusterCommand",
    executables=[exe],
    options={
        "build_exe": {
            "packages": ["paramiko", "yaml", "os", "pathlib"],
            "build_exe": "build/ClusterCommand"
        }
    },
)

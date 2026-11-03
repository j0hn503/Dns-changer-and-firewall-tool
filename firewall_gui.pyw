"""Windowed launcher: double-click this file to start the app without a console.

Python installs .pyw files with pythonw.exe, which creates no console window.
The app itself stays in firewall_gui.py.
"""

import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.argv[0] = os.path.join(HERE, "firewall_gui.py")
runpy.run_path(sys.argv[0], run_name="__main__")

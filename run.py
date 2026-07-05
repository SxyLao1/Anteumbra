#!/usr/bin/env python3
"""
Anteumbra v1.0 — Full Application Runner
Starts: Flask web server + File monitor + Log monitor + WAF poller + Profile consumer + Plugin system

v1.0.10: 启动逻辑已提取到 anteumbra.application.launcher，本文件保留向后兼容。
"""
import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from anteumbra.application.launcher import start_all

if __name__ == "__main__":
    start_all()

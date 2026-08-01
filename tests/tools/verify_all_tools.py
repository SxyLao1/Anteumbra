# -*- coding: utf-8 -*-
"""
Trident Tools Syntax Test
验证所有 tools/*.py 都能正常 import（不执行功能）
"""

import importlib
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")

# Tools that require runtime environment (skip syourusername test)
SKIP_Syntax = {"generate_demo_data.py", "ci_quick_validator.py"}


def main():
    print("Trident Tools Verification")
    print("=" * 50)

    tools = [f for f in os.listdir(TOOLS_DIR) if f.endswith(".py") and not f.startswith("_")]
    passed = 0
    failed = 0
    failed_details = []

    for tool in sorted(tools):
        if tool in SKIP_Syntax:
            print(f"  [SKIP] {tool:<35} skipped (requires runtime)")
            continue

        module_name = f"tools.{tool[:-3]}"
        try:
            importlib.import_module(module_name)
            print(f"  [OK] {tool:<35} import OK")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {tool:<35} import FAILED")
            failed += 1
            err_msg = f"{type(e).__name__}: {str(e)[:200]}"
            failed_details.append((tool, err_msg))
            # 同时打印 traceback 到 stderr，确保 GitHub 日志能看到
            import traceback

            traceback.print_exc()

    print("=" * 50)
    print(f"Result: {passed} passed, {failed} failed")

    # 强制在末尾打印失败详情，避免被日志截断
    if failed_details:
        print("\n" + "!" * 50)
        print("FAILED TOOLS DETAILS:")
        for tool, err in failed_details:
            print(f"  - {tool}: {err}")
        print("!" * 50)

    if failed > 0:
        print("\nError: Some tools are broken. Fix before release.")
        sys.exit(1)
    else:
        print("\n[OK] All tools verified.")


if __name__ == "__main__":
    main()

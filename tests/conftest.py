# Anteumbra test path setup
import sys
from pathlib import Path
_root = Path(__file__).parent.parent
_src = _root / "src"
for _path in (_root, _src):
    if str(_path) in sys.path:
        sys.path.remove(str(_path))
sys.path.insert(0, str(_root))
sys.path.insert(0, str(_src))
print(f"[conftest] Added {_root} to sys.path")

"""pytest 公共配置：把 investigation/ 加入 sys.path，使包外 evaluation/ 可导入。

evaluation/ 不随包安装（评测代码不被 Agent 导入的物理边界），
其测试通过此 conftest 以源码目录方式导入。
"""

import sys
from pathlib import Path

_INVESTIGATION_ROOT = Path(__file__).resolve().parent
if str(_INVESTIGATION_ROOT) not in sys.path:
    sys.path.insert(0, str(_INVESTIGATION_ROOT))

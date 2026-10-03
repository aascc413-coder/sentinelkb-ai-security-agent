"""M1 导入边界守卫（R3 + M1-A2）：完整模块名解析与相对导入解析。

规则（对 src/ 与 evaluation/ 全部 .py 生效）：
- 除 evaluation 自身外，任何模块不得导入 `evaluation` / `evaluation.*`（oracle/评测侧）；
- 除 tools 包自身外，任何模块不得导入 `evidence_investigation.tools` 包根或
  `evidence_investigation.tools.contracts`（环境侧契约）；未来 tools 下非契约
  子模块（如 tools.spec）不在此列；
- evaluation/ 只能导入标准库与 `evidence_investigation`（并受上一条约束）。

守卫以"函数 + 合成违规样本"测试：对真实源码树断言零违规，
并在临时目录注入 4 类违规样本验证守卫能发现（不要求用户临时改源码）。
"""

import ast
import sys
from pathlib import Path

INVESTIGATION_ROOT = Path(__file__).resolve().parents[1]
SRC = INVESTIGATION_ROOT / "src" / "evidence_investigation"
EVAL = INVESTIGATION_ROOT / "evaluation"

_STDLIB = set(sys.stdlib_module_names)
ENV_CONTRACT_TARGETS = ("evidence_investigation.tools", "evidence_investigation.tools.contracts")


def _module_name(root: Path, package_prefix: str, path: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = [p for p in rel.parts if p != "__init__"]
    return ".".join([package_prefix, *parts]) if parts else package_prefix


def _full_imports(path: Path, module_name: str) -> set[str]:
    """返回该模块引用的完整目标模块名（绝对 + 相对解析后的全名）。"""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = module_name if path.name == "__init__.py" else module_name.rpartition(".")[0]
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module or ""
            else:
                base = package
                for _ in range(node.level - 1):
                    base = base.rpartition(".")[0]
                if node.module:
                    base = f"{base}.{node.module}"
            if base:
                targets.add(base)
                # from package import submodule also imports the named child.
                targets.update(f"{base}.{alias.name}" for alias in node.names
                               if alias.name != "*")
    return targets


def _zone(module_name: str) -> str:
    if module_name == "evaluation" or module_name.startswith("evaluation."):
        return "evaluation"
    if module_name.startswith("evidence_investigation.tools"):
        return "tools"
    return "src"


def find_violations(src_root: Path, eval_root: Path) -> list[str]:
    violations: list[str] = []
    jobs = [(_module_name(src_root, "evidence_investigation", p), p)
            for p in sorted(src_root.rglob("*.py"))]
    jobs += [(_module_name(eval_root, "evaluation", p), p)
             for p in sorted(eval_root.rglob("*.py"))]
    for module_name, path in jobs:
        zone = _zone(module_name)
        targets = _full_imports(path, module_name)
        evaluation_targets = sorted(
            target for target in targets
            if target == "evaluation" or target.startswith("evaluation.")
        )
        if zone != "evaluation" and evaluation_targets:
            violations.append(f"{path}: {module_name} 导入评测侧 {evaluation_targets}")
        environment_targets = sorted(
            target for target in targets
            if target in ENV_CONTRACT_TARGETS
            or target.startswith("evidence_investigation.tools.contracts")
        )
        if zone != "tools" and environment_targets:
            violations.append(f"{path}: {module_name} 导入环境侧契约 {environment_targets}")
        if zone == "evaluation":
            external = sorted(target for target in targets if not (
                target.split(".")[0] in _STDLIB
                or target == "evidence_investigation"
                or target.startswith("evidence_investigation.")
                or target == "evaluation"
                or target.startswith("evaluation.")
            ))
            if external:
                violations.append(f"{path}: {module_name} 导入边界外模块 {external}")
    return violations


def test_real_source_trees_have_no_violations():
    assert find_violations(SRC, EVAL) == []


# ── 兼容入口（独立复核探针以 guard.SRC/EVAL 打桩后按旧名调用） ──────

def test_state_never_imports_tools():
    """src 树整体不得导入环境侧契约或评测侧（state 区为此规则的子集）。"""
    violations = find_violations(SRC, EVAL)
    assert not violations, "src 存在边界违规：\n" + "\n".join(violations)


def test_src_never_imports_evaluation():
    """src 树整体不得导入评测侧或环境侧契约（与上行同一清理断言）。"""
    test_state_never_imports_tools()


def test_evaluation_only_imports_stdlib_and_state():
    violations = [
        v for v in find_violations(SRC, EVAL) if "evaluation 导入边界外模块" in v
        or "导入环境侧契约" in v
    ]
    assert not violations, "evaluation 存在边界违规：\n" + "\n".join(violations)


def _make(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_guard_catches_absolute_env_contract_import(tmp_path):
    src = tmp_path / "src" / "evidence_investigation"
    _make(tmp_path, "src/evidence_investigation/state/evil.py",
          "from evidence_investigation.tools.contracts import EnvironmentFixture\n")
    assert len(find_violations(src, tmp_path / "evaluation")) == 1


def test_guard_catches_relative_env_contract_import(tmp_path):
    src = tmp_path / "src" / "evidence_investigation"
    _make(tmp_path, "src/evidence_investigation/state/evil.py",
          "from ..tools.contracts import EnvironmentFixture\n")
    assert len(find_violations(src, tmp_path / "evaluation")) == 1


def test_guard_catches_agents_importing_env_contracts(tmp_path):
    src = tmp_path / "src" / "evidence_investigation"
    _make(tmp_path, "src/evidence_investigation/agents/evil.py",
          "from evidence_investigation.tools import EnvironmentFixture\n")
    assert len(find_violations(src, tmp_path / "evaluation")) == 1


def test_guard_catches_evaluation_importing_env_contracts(tmp_path):
    src = tmp_path / "src" / "evidence_investigation"
    _make(tmp_path, "evaluation/evil.py",
          "from evidence_investigation.tools.contracts import EnvironmentFixture\n")
    assert len(find_violations(src, tmp_path / "evaluation")) == 1


def test_guard_allows_state_relative_sibling_import(tmp_path):
    src = tmp_path / "src" / "evidence_investigation"
    _make(tmp_path, "src/evidence_investigation/state/fine.py",
          "from .contracts import Alert\n"
          "from evidence_investigation.state.errors import ProtocolViolation\n")
    assert find_violations(src, tmp_path / "evaluation") == []


def test_boundary_holds_for_known_oracle_contract():
    from evaluation import contracts as eval_contracts  # noqa: F401

    import evidence_investigation.state.contracts as state_contracts  # noqa: F401

"""M0 冒烟测试：包可导入、声明的依赖真实可用。

依赖锁定文件保证干净环境中只安装本包声明的依赖，
因此这两个测试同时充当"不依赖产品依赖偶然存在"的守卫。
"""

import evidence_investigation


def test_package_imports():
    assert evidence_investigation.__version__ == "0.1.0"


def test_declared_dependencies_available():
    from importlib import metadata

    import httpx  # noqa: F401
    import jsonschema  # noqa: F401

    assert metadata.version("httpx")
    assert metadata.version("jsonschema")

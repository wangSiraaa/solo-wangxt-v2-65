import pytest


def pytest_addoption(parser):
    parser.addoption("--run-frr", action="store_true", help="运行真实 FRR 容器交叉验证")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-frr"):
        skip = pytest.mark.skip(reason="需要 --run-frr（本机 docker + frrouting/frr 镜像）")
        for item in items:
            if "frr_enabled" in item.fixturenames:
                item.add_marker(skip)

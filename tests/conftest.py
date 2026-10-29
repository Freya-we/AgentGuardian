"""pytest 全局夹具：隔离进程内共享状态。

**问题现象**：单跑某个用例通过，全量跑时 `test_server_events.py` 挂 10 个，
报错都是 `block` + 原因 `请求频率超限，请稍后重试`。

**根因**：`src.engine.server` 里的状态是模块级单例，其中
`_rate_buckets`（限流桶）按"调用方身份"计数，开发模式无令牌时身份统一为 `"dev"`。
而 `tests/integration/test_e2e_chain.py` 没有平台 skip、在 Windows 上也会真跑，
它按三种攻击场景走了几十个 HTTP `sign` 请求，把 `"dev"` 这个 60 令牌/分钟的桶烧光。
pytest 按目录字母序先跑 `integration/`，于是后面的 `test_server_events.py`
里所有走 sign 路径的用例都被限流挡成 `block`。

**修法**：每个用例前后清空限流桶，让结果与执行顺序、其它文件的请求量无关。
这是测试隔离问题，不是限流逻辑本身的问题——生产环境一个令牌对应一个桶是预期行为。
"""

import pytest

from src.engine import server


@pytest.fixture(autouse=True)
def _isolate_rate_limit_buckets():
    """每个用例前清空限流桶，避免跨文件互相耗尽配额。"""
    server._rate_buckets.clear()
    yield
    server._rate_buckets.clear()

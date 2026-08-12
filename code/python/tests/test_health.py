import pytest

from api.main import health, runtime_status


@pytest.mark.asyncio
async def test_health_reports_degraded_component_instead_of_false_ok():
    previous = {name: value.copy() for name, value in runtime_status.items()}
    try:
        runtime_status["vector_store"] = {"status": "ready", "detail": None}
        runtime_status["knowledge_graph"] = {
            "status": "unavailable",
            "detail": "ConnectionRefusedError",
        }
        runtime_status["workflows"] = {"status": "ready", "detail": None}

        result = await health()

        assert result["status"] == "degraded"
        assert result["components"]["knowledge_graph"]["status"] == "unavailable"
        assert "ConnectionRefusedError" in result["components"]["knowledge_graph"]["detail"]
    finally:
        runtime_status.clear()
        runtime_status.update(previous)


@pytest.mark.asyncio
async def test_health_is_ok_only_when_all_components_are_ready():
    previous = {name: value.copy() for name, value in runtime_status.items()}
    try:
        for name in runtime_status:
            runtime_status[name] = {"status": "ready", "detail": None}

        result = await health()

        assert result["status"] == "ok"
    finally:
        runtime_status.clear()
        runtime_status.update(previous)

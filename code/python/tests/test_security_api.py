from fastapi.testclient import TestClient

from api.main import app


client = TestClient(app)


def test_security_analysis_endpoint_works_without_llm_or_databases():
    response = client.post(
        "/api/security/analyze",
        json={
            "text": "PowerShell EncodedCommand 回连 https://evil-example.top/a，疑似凭证转储。",
            "source": "api-test",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "api-test"
    assert any(item["technique_id"] == "T1059.001" for item in body["techniques"])
    assert any(item["type"] == "url" for item in body["indicators"])


def test_security_analysis_endpoint_rejects_blank_text():
    response = client.post(
        "/api/security/analyze",
        json={"text": "   ", "source": "api-test"},
    )

    assert response.status_code == 422
    assert "不能为空" in response.json()["detail"]

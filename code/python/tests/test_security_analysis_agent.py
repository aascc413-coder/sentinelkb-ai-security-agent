import pytest

from agents.security_analysis_agent import SecurityAnalysisAgent


@pytest.mark.asyncio
async def test_extracts_iocs_and_attack_techniques():
    text = (
        "检测到 PowerShell EncodedCommand 执行并访问 http://evil-example.top/a，"
        "源地址 203.0.113.10，疑似 Mimikatz 凭证转储和横向移动。"
        "样本 SHA256 为 " + "a" * 64 + "，关联 CVE-2025-12345。"
    )
    result = await SecurityAnalysisAgent().analyze(text, "unit-test")

    values = {item.value for item in result.indicators}
    technique_ids = {item.technique_id for item in result.techniques}
    assert "203.0.113.10" in values
    assert "CVE-2025-12345" in values
    assert "T1059.001" in technique_ids
    assert "T1003" in technique_ids
    assert result.severity in {"high", "critical"}
    assert result.recommendations


@pytest.mark.asyncio
async def test_rejects_empty_input():
    with pytest.raises(ValueError, match="不能为空"):
        await SecurityAnalysisAgent().analyze("   ")

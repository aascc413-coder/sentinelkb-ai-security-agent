"""安全研判 Agent：IOC 提取、ATT&CK 映射、风险评分与处置建议。

该模块使用确定性规则完成第一阶段研判，不依赖外部大模型，便于离线演示、
单元测试和审计。LLM/RAG 负责结合企业私有知识生成解释，两者职责分离。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class Indicator:
    type: str
    value: str
    confidence: float = 0.9


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str
    name: str
    tactic: str
    evidence: str


@dataclass
class SecurityAnalysis:
    risk_score: int
    severity: str
    indicators: list[Indicator] = field(default_factory=list)
    techniques: list[AttackTechnique] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    summary: str = ""
    source: str = "manual"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SecurityAnalysisAgent:
    """面向告警、事件报告、漏洞通告的轻量级安全研判智能体。"""

    _PATTERNS = {
        "url": re.compile(r"https?://[^\s<>'\"，。；]+", re.IGNORECASE),
        "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
        "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
        "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
        "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
        "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        "ipv4": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
        "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|cn|io|top|xyz|ru|info|biz|cc)\b", re.IGNORECASE),
    }

    _TECHNIQUE_RULES = (
        (("钓鱼", "phishing", "恶意附件", "鱼叉式"), "T1566", "Phishing", "Initial Access"),
        (("powershell", "pwsh", "encodedcommand"), "T1059.001", "PowerShell", "Execution"),
        (("混淆", "obfuscated", "base64", "编码载荷"), "T1027", "Obfuscated Files or Information", "Defense Evasion"),
        (("mimikatz", "凭证转储", "credential dumping", "lsass"), "T1003", "OS Credential Dumping", "Credential Access"),
        (("计划任务", "scheduled task", "schtasks"), "T1053.005", "Scheduled Task/Job", "Persistence"),
        (("横向移动", "psexec", "smb", "远程服务"), "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
        (("webshell", "web shell", "蚁剑", "冰蝎"), "T1505.003", "Web Shell", "Persistence"),
        (("勒索", "ransomware", "文件加密"), "T1486", "Data Encrypted for Impact", "Impact"),
        (("数据外传", "exfiltration", "信息窃取", "窃密"), "T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        (("c2", "command and control", "命令与控制", "回连"), "T1071.001", "Web Protocols", "Command and Control"),
        (("漏洞利用", "exploit", "对外服务"), "T1190", "Exploit Public-Facing Application", "Initial Access"),
    )

    _HIGH_RISK_TERMS = (
        "勒索", "ransomware", "数据外传", "exfiltration", "域控", "domain controller",
        "mimikatz", "webshell", "远程代码执行", "remote code execution", "0day", "零日",
    )

    def __init__(self) -> None:
        self._analyses = 0
        self._indicators = 0
        self._high_risk = 0

    async def analyze(self, text: str, source: str = "manual") -> SecurityAnalysis:
        if not text or not text.strip():
            raise ValueError("待分析文本不能为空")
        if len(text) > 200_000:
            raise ValueError("单次研判文本不能超过 200000 个字符")

        indicators = self._extract_indicators(text)
        techniques = self._map_attack(text)
        score = self._score(text, indicators, techniques)
        severity = self._severity(score)
        recommendations = self._recommend(severity, indicators, techniques)
        result = SecurityAnalysis(
            risk_score=score,
            severity=severity,
            indicators=indicators,
            techniques=techniques,
            recommendations=recommendations,
            summary=self._summarize(severity, indicators, techniques),
            source=source,
        )
        self._analyses += 1
        self._indicators += len(indicators)
        if severity in {"high", "critical"}:
            self._high_risk += 1
        return result

    def get_stats(self) -> dict[str, int]:
        return {
            "total_analyses": self._analyses,
            "total_indicators": self._indicators,
            "high_risk_events": self._high_risk,
        }

    def _extract_indicators(self, text: str) -> list[Indicator]:
        found: dict[tuple[str, str], Indicator] = {}
        urls: set[str] = set()
        for value in self._PATTERNS["url"].findall(text):
            value = value.rstrip(".,;)")
            urls.add(value)
            found[("url", value.lower())] = Indicator("url", value, 0.98)

        for kind in ("cve", "sha256", "sha1", "md5", "email", "ipv4", "domain"):
            for raw in self._PATTERNS[kind].findall(text):
                value = raw.rstrip(".,;)")
                if kind == "ipv4":
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        continue
                if kind == "domain" and any(urlparse(url).hostname == value.lower() for url in urls):
                    continue
                normalized = value.upper() if kind == "cve" else value.lower()
                found[(kind, normalized)] = Indicator(kind, normalized)
        return sorted(found.values(), key=lambda item: (item.type, item.value))

    def _map_attack(self, text: str) -> list[AttackTechnique]:
        lowered = text.lower()
        mapped: list[AttackTechnique] = []
        for keywords, technique_id, name, tactic in self._TECHNIQUE_RULES:
            evidence = next((word for word in keywords if word.lower() in lowered), "")
            if evidence:
                mapped.append(AttackTechnique(technique_id, name, tactic, evidence))
        return mapped

    def _score(self, text: str, indicators: list[Indicator], techniques: list[AttackTechnique]) -> int:
        lowered = text.lower()
        score = min(len(indicators) * 4, 24) + min(len(techniques) * 9, 45)
        score += min(sum(1 for word in self._HIGH_RISK_TERMS if word in lowered) * 10, 30)
        if any(item.type in {"sha256", "sha1", "md5"} for item in indicators):
            score += 7
        if any(item.type == "cve" for item in indicators):
            score += 6
        return min(score, 100)

    @staticmethod
    def _severity(score: int) -> str:
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"

    @staticmethod
    def _recommend(
        severity: str,
        indicators: list[Indicator],
        techniques: list[AttackTechnique],
    ) -> list[str]:
        actions = ["保留原始日志、告警上下文与时间线，避免破坏取证证据。"]
        if severity in {"critical", "high"}:
            actions.insert(0, "立即隔离疑似受影响主机，并由安全人员复核后执行阻断。")
        if indicators:
            actions.append("将提取出的 IOC 与 EDR、DNS、代理和防火墙日志做全量回溯检索。")
        if any(t.tactic == "Credential Access" for t in techniques):
            actions.append("检查凭证滥用范围，轮换受影响账户并审计高权限登录。")
        if any(t.tactic == "Lateral Movement" for t in techniques):
            actions.append("核查东西向流量、远程服务和共享访问，评估横向移动范围。")
        if any(t.tactic == "Impact" for t in techniques):
            actions.append("验证离线备份可用性，暂停自动同步以防止加密文件扩散。")
        actions.append("处置结论需由授权安全人员确认；本结果仅用于辅助研判。")
        return actions

    @staticmethod
    def _summarize(
        severity: str,
        indicators: list[Indicator],
        techniques: list[AttackTechnique],
    ) -> str:
        return (
            f"研判等级 {severity.upper()}；发现 {len(indicators)} 个 IOC，"
            f"映射 {len(techniques)} 个 ATT&CK 技术。"
        )

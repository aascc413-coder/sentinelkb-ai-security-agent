"""
问答 Agent — 混合检索 (Vector + Graph) + 多跳推理 + 答案生成

核心能力:
  1. 意图识别 & 查询改写
  2. 向量检索 (语义相似度)
  3. 图谱检索 (Cypher 查询 / 子图遍历)
  4. 混合排序 & 重排序
  5. 基于检索结果的答案生成（带引用来源）
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from config import settings


class QueryIntent(str, Enum):
    FACTOID = "factoid"           # 事实型问题
    ANALYTICAL = "analytical"     # 分析型问题
    COMPARATIVE = "comparative"   # 对比型问题
    PROCEDURAL = "procedural"     # 流程型问题
    EXPLORATORY = "exploratory"   # 探索型问题


@dataclass
class RetrievedContext:
    content: str
    source: str
    score: float
    retrieval_type: str  # "vector" | "graph" | "hybrid"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class QAResult:
    question: str
    answer: str
    contexts: list[RetrievedContext]
    intent: QueryIntent
    confidence: float
    reasoning_steps: list[str] = field(default_factory=list)


INTENT_PROMPT = """\
你是一个查询意图分类器。根据用户问题，返回意图类别（只返回类别名）：
- factoid: 事实型（谁/什么/哪里/何时）
- analytical: 分析型（为什么/怎么理解）
- comparative: 对比型（A和B有什么区别）
- procedural: 流程型（怎么做/步骤）
- exploratory: 探索型（有哪些/概述）
"""

QUERY_REWRITE_PROMPT = """\
你是一个查询改写专家。将用户问题改写为更适合检索的形式。
要求：
1. 提取核心实体和关键词
2. 生成 1-3 个检索查询
3. 返回 JSON: {"queries": ["查询1", "查询2"], "entities": ["实体1"], "keywords": ["关键词1"]}
"""

CYPHER_GENERATION_PROMPT = """\
你是一个 Neo4j Cypher 查询生成专家。根据用户问题和提取的实体，生成 Cypher 查询。

知识图谱 Schema:
- 节点标签: Entity（type 属性区分 ThreatActor、Malware、Vulnerability、Asset、AttackTechnique、IOC、SecurityControl 等）
- 关系类型: exploits, targets, affects, communicates_with, mitigates, attributed_to, indicates, related_to, uses
- 节点属性: name, type, description, created_at, version

只允许生成只读 MATCH ... RETURN 查询。生成 1-2 条 Cypher 查询，返回 JSON: {"queries": ["MATCH ...", "MATCH ..."]}
只返回 JSON，不要其他文字。
"""

ANSWER_PROMPT = """\
你是企业安全运营中心的 AI 分析助手。根据检索到的私有安全知识回答用户问题。

要求：
1. 答案必须基于提供的上下文，不要编造
2. 如果上下文信息不足，明确告知用户
3. 引用信息来源（如 [来源: xxx]）
4. 如果涉及多个信息源，综合分析后给出结论
5. 保持专业、准确、简洁
6. 区分事实、推断和建议；高风险处置操作必须提示人工确认
"""


class QAAgent:
    """
    问答 Agent

    工作流:
      query → intent_classify → rewrite → parallel_retrieve → rerank → generate_answer
    """

    def __init__(
        self,
        vector_store: Any = None,
        knowledge_graph: Any = None,
    ) -> None:
        self.llm = None
        if settings.llm_configured:
            self.llm = ChatOpenAI(
                model=settings.openai_model,
                api_key=settings.openai_api_key,
                base_url=settings.openai_base_url,
                temperature=0,
            )
        self.vector_store = vector_store
        self.knowledge_graph = knowledge_graph

    # ── public API ───────────────────────────────────────────

    async def answer(self, question: str) -> QAResult:
        """完整问答流程"""
        intent = await self._classify_intent(question)
        rewritten = await self._rewrite_query(question)

        vector_contexts = await self._vector_retrieve(rewritten)
        graph_contexts = await self._graph_retrieve(question, rewritten)

        all_contexts = self._hybrid_rerank(vector_contexts + graph_contexts)
        top_contexts = all_contexts[:8]

        answer_text, reasoning = await self._generate_answer(question, top_contexts, intent)

        return QAResult(
            question=question,
            answer=answer_text,
            contexts=top_contexts,
            intent=intent,
            confidence=self._calc_confidence(top_contexts),
            reasoning_steps=reasoning,
        )

    # ── intent classification ────────────────────────────────

    async def _classify_intent(self, question: str) -> QueryIntent:
        if self.llm is None:
            if any(word in question for word in ("怎么", "如何", "步骤", "流程")):
                return QueryIntent.PROCEDURAL
            if any(word in question for word in ("区别", "比较", "对比")):
                return QueryIntent.COMPARATIVE
            if any(word in question for word in ("为什么", "分析", "原因")):
                return QueryIntent.ANALYTICAL
            return QueryIntent.FACTOID
        messages = [
            SystemMessage(content=INTENT_PROMPT),
            HumanMessage(content=question),
        ]
        resp = await self.llm.ainvoke(messages)
        raw = resp.content.strip().lower()
        for intent in QueryIntent:
            if intent.value in raw:
                return intent
        return QueryIntent.FACTOID

    # ── query rewriting ──────────────────────────────────────

    async def _rewrite_query(self, question: str) -> dict:
        import json
        if self.llm is None:
            return {"queries": [question], "entities": [], "keywords": []}
        messages = [
            SystemMessage(content=QUERY_REWRITE_PROMPT),
            HumanMessage(content=question),
        ]
        resp = await self.llm.ainvoke(messages)
        try:
            cleaned = resp.content.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0]
            return json.loads(cleaned)
        except (json.JSONDecodeError, IndexError):
            return {"queries": [question], "entities": [], "keywords": []}

    # ── vector retrieval ─────────────────────────────────────

    async def _vector_retrieve(self, rewritten: dict) -> list[RetrievedContext]:
        if not self.vector_store:
            return []

        contexts: list[RetrievedContext] = []
        for query in rewritten.get("queries", []):
            results = await self.vector_store.search(query, top_k=5)
            for doc, score in results:
                contexts.append(RetrievedContext(
                    content=doc.get("content", ""),
                    source=doc.get("source", "vector_store"),
                    score=score,
                    retrieval_type=doc.get("retrieval_type", "vector"),
                    metadata=doc.get("metadata", {}),
                ))
        return contexts

    # ── graph retrieval ──────────────────────────────────────

    async def _graph_retrieve(self, question: str, rewritten: dict) -> list[RetrievedContext]:
        if not self.knowledge_graph or self.llm is None:
            return []

        import json
        entities = rewritten.get("entities", [])
        messages = [
            SystemMessage(content=CYPHER_GENERATION_PROMPT),
            HumanMessage(content=f"问题: {question}\n实体: {entities}"),
        ]
        resp = await self.llm.ainvoke(messages)
        try:
            cleaned = resp.content.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0]
            cypher_data = json.loads(cleaned)
        except (json.JSONDecodeError, IndexError):
            cypher_data = {"queries": []}

        contexts: list[RetrievedContext] = []
        for cypher in cypher_data.get("queries", []):
            try:
                records = await self.knowledge_graph.execute_read_cypher(cypher)
                for record in records:
                    contexts.append(RetrievedContext(
                        content=str(record),
                        source="knowledge_graph",
                        score=0.8,
                        retrieval_type="graph",
                        metadata={"cypher": cypher},
                    ))
            except Exception:
                continue
        return contexts

    # ── hybrid reranking ─────────────────────────────────────

    @staticmethod
    def _hybrid_rerank(contexts: list[RetrievedContext]) -> list[RetrievedContext]:
        """
        混合重排序：向量分数 + 图谱分数加权
        图谱检索结果天然带有结构化关系，给予略高权重
        """
        weight_map = {"vector": 1.0, "graph": 1.2, "hybrid": 1.1}
        for ctx in contexts:
            ctx.score *= weight_map.get(ctx.retrieval_type, 1.0)

        seen: set[str] = set()
        unique: list[RetrievedContext] = []
        for ctx in contexts:
            key = ctx.content[:100]
            if key not in seen:
                seen.add(key)
                unique.append(ctx)

        unique.sort(key=lambda c: c.score, reverse=True)
        return unique

    # ── answer generation ────────────────────────────────────

    async def _generate_answer(
        self,
        question: str,
        contexts: list[RetrievedContext],
        intent: QueryIntent,
    ) -> tuple[str, list[str]]:
        context_text = "\n\n".join(
            f"[来源 {i+1}: {c.source} | 类型: {c.retrieval_type} | 分数: {c.score:.2f}]\n{c.content}"
            for i, c in enumerate(contexts)
        )
        reasoning_steps = [
            f"识别问题意图: {intent.value}",
            f"检索到 {len(contexts)} 条相关上下文",
            f"向量检索: {sum(1 for c in contexts if c.retrieval_type == 'vector')} 条",
            f"词法检索: {sum(1 for c in contexts if c.retrieval_type == 'lexical')} 条",
            f"图谱检索: {sum(1 for c in contexts if c.retrieval_type == 'graph')} 条",
        ]

        if self.llm is None:
            if not contexts:
                return (
                    "离线检索未找到相关内容。请先上传包含该知识的文档，或配置模型服务以启用生成式回答。",
                    reasoning_steps + ["离线模式：未调用大模型"],
                )
            excerpts = "\n\n".join(
                f"[来源: {context.source}] {context.content}" for context in contexts[:3]
            )
            return (
                f"以下是知识库中与问题相关的原文片段（离线模式，未经大模型改写）：\n\n{excerpts}",
                reasoning_steps + ["离线模式：返回可追溯原文片段"],
            )

        if contexts:
            system_prompt = ANSWER_PROMPT
            user_prompt = f"上下文信息:\n{context_text}\n\n用户问题: {question}"
        else:
            system_prompt = "你是企业安全运营中心的 AI 分析助手。当前私有知识库没有命中内容，请明确说明这一点，再给出通用防御性建议；不要伪造企业内部事实。"
            user_prompt = question
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ]
        resp = await self.llm.ainvoke(messages)
        reasoning_steps.append("答案生成完成")
        return resp.content, reasoning_steps

    @staticmethod
    def _calc_confidence(contexts: list[RetrievedContext]) -> float:
        if not contexts:
            return 0.0
        avg_score = sum(c.score for c in contexts) / len(contexts)
        return min(avg_score, 1.0)

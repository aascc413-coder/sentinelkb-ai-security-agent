from pathlib import Path

import pytest

from agents.knowledge_extract_agent import KnowledgeExtractAgent
from agents.qa_agent import QAAgent
from orchestrator.graph import build_knowledge_graph_workflow


class FakeVectorStore:
    def __init__(self):
        self.chunks = []

    async def add_chunks(self, chunks):
        self.chunks.extend(chunks)
        return len(chunks)

    async def search(self, query, top_k=5):
        return [
            (
                {
                    "content": "应急处置时应隔离受影响主机并保留日志。",
                    "source": "应急预案.txt",
                    "metadata": {"doc_id": "doc-1"},
                    "retrieval_type": "lexical",
                },
                0.9,
            )
        ]


class FakeKnowledgeGraph:
    def __init__(self):
        self.entities = []
        self.relations = []

    async def upsert_entity(self, entity, source=""):
        self.entities.append(entity)

    async def add_relation(self, relation, source=""):
        self.relations.append(relation)


@pytest.mark.asyncio
async def test_offline_extraction_builds_a_traceable_rule_based_security_graph():
    extractor = KnowledgeExtractAgent()

    result = await extractor.extract_single("包含 PowerShell 行为的安全报告", "chunk-1")

    assert extractor.available is False
    assert result.source_chunk_id == "chunk-1"
    assert any(entity.type == "Event" for entity in result.entities)
    assert any(entity.type == "AttackTechnique" for entity in result.entities)
    assert any(relation.relation == "uses_technique" for relation in result.relations)


@pytest.mark.asyncio
async def test_offline_ingest_still_parses_and_indexes_text(tmp_path: Path):
    document = tmp_path / "incident.txt"
    document.write_text("发现可疑 PowerShell 行为，应隔离主机并保留日志。", encoding="utf-8")
    vector_store = FakeVectorStore()
    knowledge_graph = FakeKnowledgeGraph()
    workflows = build_knowledge_graph_workflow(vector_store, knowledge_graph)

    result = await workflows["ingest"].ainvoke({
        "file_paths": [str(document)],
        "source_names": {str(document): "事件报告.txt"},
    })

    assert result["chunks"]
    assert result["vectors_stored"] == len(result["chunks"])
    assert result["extraction_status"] == "offline_rules"
    assert vector_store.chunks[0].metadata["source"] == "事件报告.txt"
    assert vector_store.chunks[0].metadata["stored_path"] == str(document)
    assert knowledge_graph.entities
    assert knowledge_graph.relations
    assert result["relations_stored"] == len(knowledge_graph.relations)
    assert result["vector_store_error"] is None
    assert result["knowledge_graph_error"] is None


@pytest.mark.asyncio
async def test_offline_qa_returns_retrieved_source_without_fabricating_an_answer():
    agent = QAAgent(vector_store=FakeVectorStore())

    result = await agent.answer("发生安全事件后如何处置？")

    assert "离线模式" in result.answer
    assert "应急预案.txt" in result.answer
    assert result.contexts[0].source == "应急预案.txt"
    assert result.intent.value == "procedural"
    assert "词法检索: 1 条" in result.reasoning_steps

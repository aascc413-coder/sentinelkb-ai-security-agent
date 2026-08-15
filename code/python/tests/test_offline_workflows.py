from pathlib import Path

import pytest

from agents.doc_parser_agent import DocParserAgent
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


def test_document_id_depends_on_content_not_temporary_upload_path(tmp_path: Path):
    first = tmp_path / "first.txt"
    second = tmp_path / "random-prefix_second.txt"
    content = "相同的安全处置规范。"
    first.write_text(content, encoding="utf-8")
    second.write_text(content, encoding="utf-8")

    assert DocParserAgent._make_doc_id(str(first)) == DocParserAgent._make_doc_id(str(second))


@pytest.mark.asyncio
async def test_ingest_commits_graph_before_marking_vector_index_complete(tmp_path: Path):
    events: list[str] = []

    class OrderedVectorStore(FakeVectorStore):
        async def add_chunks(self, chunks):
            events.append("vector")
            return await super().add_chunks(chunks)

    class AtomicKnowledgeGraph:
        async def store_extractions(self, extractions):
            events.append("graph")
            return (
                sum(len(item.entities) for item in extractions),
                sum(len(item.relations) for item in extractions),
            )

    document = tmp_path / "ordered.txt"
    document.write_text("发现 PowerShell 异常行为。", encoding="utf-8")
    workflows = build_knowledge_graph_workflow(OrderedVectorStore(), AtomicKnowledgeGraph())

    result = await workflows["ingest"].ainvoke({"file_paths": [str(document)]})

    assert events == ["graph", "vector"]
    assert result["knowledge_graph_error"] is None
    assert result["vector_store_error"] is None


@pytest.mark.asyncio
async def test_offline_qa_returns_retrieved_source_without_fabricating_an_answer():
    agent = QAAgent(vector_store=FakeVectorStore())

    result = await agent.answer("发生安全事件后如何处置？")

    assert "离线模式" in result.answer
    assert "应急预案.txt" in result.answer
    assert result.contexts[0].source == "应急预案.txt"
    assert result.intent.value == "procedural"
    assert "词法检索: 1 条" in result.reasoning_steps


@pytest.mark.asyncio
async def test_graph_retrieval_uses_local_entity_lookup_without_llm():
    class SearchableGraph:
        async def search_entities(self, keyword, limit=5):
            assert keyword == "SEC-731"
            return [{"name": "SEC-731", "type": "Event", "description": "蓝隼项目安全事件"}]

        async def get_neighbors(self, entity_name, hops=1):
            return [{"source": entity_name, "relations": ["USES_TECHNIQUE"], "target": "T1003"}]

    agent = QAAgent(vector_store=None, knowledge_graph=SearchableGraph())
    rewritten = await agent._rewrite_query("SEC-731 涉及哪些技术？")
    contexts = await agent._graph_retrieve("SEC-731 涉及哪些技术？", rewritten)

    assert len(contexts) == 2
    assert all(context.retrieval_type == "graph" for context in contexts)

"""
LangGraph 编排引擎 — 4 Agent 混合编排

编排模式:
  1. 文档入库流程: DocParser → KnowledgeExtract → (VectorStore + KnowledgeGraph)
  2. 问答流程: Query → QA Agent → (VectorRetrieval ∥ GraphRetrieval) → Answer
  3. 增量更新流程: CDC Event → UpdateAgent → (Diff → Parse → Store)

使用 LangGraph StateGraph 实现有向图编排，支持条件路由和并行分支
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

from agents.doc_parser_agent import DocParserAgent, DocumentChunk
from agents.knowledge_extract_agent import ExtractionResult, KnowledgeExtractAgent
from agents.knowledge_update_agent import (
    ChangeType,
    DocumentChange,
    KnowledgeUpdateAgent,
    UpdateResult,
)
from agents.qa_agent import QAAgent, QAResult
from services.knowledge_graph import KnowledgeGraphService
from services.vector_store import VectorStoreService


class WorkflowType(str, Enum):
    INGEST = "ingest"
    QA = "qa"
    UPDATE = "update"


# ── State Schemas ────────────────────────────────────────────

class IngestState(dict):
    """文档入库流程状态"""
    file_paths: list[str]
    chunks: list[DocumentChunk]
    extractions: list[ExtractionResult]
    vectors_stored: int
    entities_stored: int
    messages: Annotated[list, add_messages]


class QAState(dict):
    """问答流程状态"""
    question: str
    result: QAResult | None
    messages: Annotated[list, add_messages]


class UpdateState(dict):
    """增量更新流程状态"""
    changes: list[DocumentChange]
    results: list[UpdateResult]
    messages: Annotated[list, add_messages]


# ── Workflow Builder ─────────────────────────────────────────

def build_knowledge_graph_workflow(
    vector_store: VectorStoreService | None = None,
    knowledge_graph: KnowledgeGraphService | None = None,
) -> dict[str, Any]:
    """
    构建三条编排流水线，返回 {"ingest": graph, "qa": graph, "update": graph}
    """
    doc_parser = DocParserAgent()
    extractor = KnowledgeExtractAgent()
    qa_agent = QAAgent(vector_store=vector_store, knowledge_graph=knowledge_graph)
    update_agent = KnowledgeUpdateAgent(
        doc_parser=doc_parser,
        knowledge_extractor=extractor,
        vector_store=vector_store,
        knowledge_graph=knowledge_graph,
    )

    return {
        "ingest": _build_ingest_graph(doc_parser, extractor, vector_store, knowledge_graph),
        "qa": _build_qa_graph(qa_agent),
        "update": _build_update_graph(update_agent),
    }


# ── Ingest Pipeline ─────────────────────────────────────────

def _build_ingest_graph(
    doc_parser: DocParserAgent,
    extractor: KnowledgeExtractAgent,
    vector_store: VectorStoreService | None,
    knowledge_graph: KnowledgeGraphService | None,
) -> StateGraph:

    async def parse_documents(state: dict) -> dict:
        file_paths = state.get("file_paths", [])
        chunks = await doc_parser.parse_batch(file_paths)
        source_names = state.get("source_names", {})
        for chunk in chunks:
            stored_path = chunk.metadata.get("source", "")
            if stored_path in source_names:
                chunk.metadata["stored_path"] = stored_path
                chunk.metadata["source"] = source_names[stored_path]
        return {**state, "chunks": chunks}

    async def extract_knowledge(state: dict) -> dict:
        chunks = state.get("chunks", [])
        extractions = await extractor.extract(chunks)
        status = "llm_completed" if extractor.available else "offline_rules"
        return {**state, "extractions": extractions, "extraction_status": status}

    async def store_vectors(state: dict) -> dict:
        chunks = state.get("chunks", [])
        count = 0
        error = None
        if vector_store and chunks:
            try:
                count = await vector_store.add_chunks(chunks)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
        return {**state, "vectors_stored": count, "vector_store_error": error}

    async def store_graph(state: dict) -> dict:
        extractions = state.get("extractions", [])
        entity_count = 0
        relation_count = 0
        error = None
        if knowledge_graph:
            try:
                if hasattr(knowledge_graph, "store_extractions"):
                    entity_count, relation_count = await knowledge_graph.store_extractions(extractions)
                else:
                    for ext in extractions:
                        for ent in ext.entities:
                            await knowledge_graph.upsert_entity(ent, source=ext.source_chunk_id)
                            entity_count += 1
                        for rel in ext.relations:
                            await knowledge_graph.add_relation(rel, source=ext.source_chunk_id)
                            relation_count += 1
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
        return {
            **state,
            "entities_stored": entity_count,
            "relations_stored": relation_count,
            "knowledge_graph_error": error,
        }

    graph = StateGraph(dict)
    graph.add_node("parse", parse_documents)
    graph.add_node("extract", extract_knowledge)
    graph.add_node("store_vectors", store_vectors)
    graph.add_node("store_graph", store_graph)

    graph.set_entry_point("parse")
    graph.add_edge("parse", "extract")
    # Store the graph transaction first.  Vector/lexical indexing is the final
    # completion marker used by duplicate detection.
    graph.add_edge("extract", "store_graph")
    graph.add_edge("store_graph", "store_vectors")
    graph.add_edge("store_vectors", END)

    return graph.compile()


# ── QA Pipeline ──────────────────────────────────────────────

def _build_qa_graph(qa_agent: QAAgent) -> StateGraph:

    async def process_question(state: dict) -> dict:
        question = state.get("question", "")
        result = await qa_agent.answer(question)
        return {**state, "result": result}

    graph = StateGraph(dict)
    graph.add_node("answer", process_question)
    graph.set_entry_point("answer")
    graph.add_edge("answer", END)

    return graph.compile()


# ── Update Pipeline ──────────────────────────────────────────

def _build_update_graph(update_agent: KnowledgeUpdateAgent) -> StateGraph:

    async def process_updates(state: dict) -> dict:
        changes = state.get("changes", [])
        results = await update_agent.process_batch(changes)
        return {**state, "results": results}

    def should_continue(state: dict) -> str:
        results = state.get("results", [])
        failed = [r for r in results if not r.success]
        if failed:
            return "retry"
        return "done"

    async def retry_failed(state: dict) -> dict:
        results = state.get("results", [])
        failed_changes = [r.change for r in results if not r.success]
        retried = await update_agent.process_batch(failed_changes)
        all_results = [r for r in results if r.success] + retried
        return {**state, "results": all_results}

    graph = StateGraph(dict)
    graph.add_node("process", process_updates)
    graph.add_node("retry", retry_failed)

    graph.set_entry_point("process")
    graph.add_conditional_edges("process", should_continue, {"retry": "retry", "done": END})
    graph.add_edge("retry", END)

    return graph.compile()

import json
import os

import pytest

from agents.doc_parser_agent import DocType, DocumentChunk
from config import settings
from services.vector_store import VectorStoreService


def test_dotenv_setting_disables_remote_embeddings(monkeypatch):
    """The .env flag must work even when it is absent from os.environ."""
    monkeypatch.delenv("DISABLE_LOCAL_EMBEDDINGS", raising=False)
    monkeypatch.setattr(settings, "disable_local_embeddings", True)
    monkeypatch.setattr(settings, "openai_api_key", "sk-test-only")

    store = VectorStoreService()

    assert store.embeddings is None
    assert store.embeddings_available is False


@pytest.mark.asyncio
async def test_offline_lexical_retrieval(tmp_path, monkeypatch):
    monkeypatch.setenv("DISABLE_LOCAL_EMBEDDINGS", "1")
    store = VectorStoreService()
    store._lexical_index_path = str(tmp_path / "lexical_index.json")
    await store.add_chunks([
        DocumentChunk(
            content="应急处置要求隔离感染主机，并回溯防火墙与 EDR 日志。",
            doc_id="doc-1",
            chunk_index=0,
            doc_type=DocType.TEXT,
            metadata={"source": "应急预案.txt"},
        )
    ])

    results = await store.search("感染主机如何隔离", top_k=3)
    assert results
    assert results[0][0]["source"] == "应急预案.txt"
    assert results[0][0]["retrieval_type"] == "lexical"
    assert results[0][1] > 0


@pytest.mark.asyncio
async def test_chroma_initializes_on_python_312_without_embeddings(tmp_path, monkeypatch):
    monkeypatch.setenv("DISABLE_LOCAL_EMBEDDINGS", "1")
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path / "uploads"))
    store = VectorStoreService()

    await store.init()

    stats = await store.get_stats()
    assert store._store is not None
    assert stats["backend"] == "chroma+lexical"
    assert stats["semantic_enabled"] is False


@pytest.mark.asyncio
async def test_readding_same_content_addressed_chunk_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("DISABLE_LOCAL_EMBEDDINGS", "1")
    store = VectorStoreService()
    store._lexical_index_path = str(tmp_path / "lexical_index.json")
    chunk = DocumentChunk(
        content="蓝隼项目事件编号 SEC-731。",
        doc_id="content-hash-1",
        chunk_index=0,
        doc_type=DocType.TEXT,
        metadata={"source": "rag_test.txt"},
    )

    await store.add_chunks([chunk])
    await store.add_chunks([chunk])

    assert store.has_doc_id("content-hash-1") is True
    assert store.count_chunks_by_doc_id("content-hash-1") == 1
    assert len(store._lexical_docs) == 1


@pytest.mark.asyncio
async def test_incident_anchor_prevents_cross_event_context_mixing(tmp_path, monkeypatch):
    monkeypatch.setenv("DISABLE_LOCAL_EMBEDDINGS", "1")
    store = VectorStoreService()
    store._lexical_index_path = str(tmp_path / "lexical_index.json")
    await store.add_chunks([
        DocumentChunk(
            content="蓝隼项目事件 SEC-731 检测到 Mimikatz。",
            doc_id="blue",
            chunk_index=0,
            doc_type=DocType.TEXT,
            metadata={"source": "rag_test.txt"},
        ),
        DocumentChunk(
            content="另一事件也检测到 Mimikatz 和横向移动。",
            doc_id="other",
            chunk_index=0,
            doc_type=DocType.TEXT,
            metadata={"source": "other.txt"},
        ),
    ])

    results = await store.search("SEC-731 中 Mimikatz 如何处置？", top_k=5)

    assert [item[0]["source"] for item in results] == ["rag_test.txt"]


def test_legacy_path_ids_are_migrated_and_duplicate_content_is_collapsed(tmp_path):
    first = tmp_path / "one.txt"
    second = tmp_path / "two.txt"
    first.write_text("same content", encoding="utf-8")
    second.write_text("same content", encoding="utf-8")
    index_path = tmp_path / "lexical_index.json"
    index_path.write_text(json.dumps({
        "old-one#chunk-0": {
            "content": "same content",
            "source": str(first),
            "doc_id": "old-one",
            "metadata": {"source": str(first)},
        },
        "old-two#chunk-0": {
            "content": "same content",
            "source": "friendly.txt",
            "doc_id": "old-two",
            "metadata": {"source": "friendly.txt", "stored_path": str(second)},
        },
    }), encoding="utf-8")
    store = VectorStoreService()
    store._lexical_index_path = str(index_path)

    store._load_lexical_index()

    assert len(store._lexical_docs) == 1
    migrated = next(iter(store._lexical_docs.values()))
    assert migrated["source"] == "friendly.txt"

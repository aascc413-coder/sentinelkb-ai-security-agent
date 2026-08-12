import os

import pytest

from agents.doc_parser_agent import DocType, DocumentChunk
from config import settings
from services.vector_store import VectorStoreService


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

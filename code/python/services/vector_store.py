"""
向量存储服务 — 支持 ChromaDB / PGVector 双后端

职责:
  1. 文档块向量化 (Embedding)
  2. 向量存储 & 检索
  3. 按 doc_id 删除（支持增量更新）
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from langchain_openai import OpenAIEmbeddings

from agents.doc_parser_agent import DocumentChunk
from config import settings


class _SubprocessEmbeddings:
    """Embedding wrapper that delegates to a separate subprocess to avoid
    PyTorch segfaults from crashing the main server process."""

    def __init__(self):
        from services.embedding_worker import get_embedding_client
        self._client = get_embedding_client()

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if self._client is None:
            return [[0.0]] * len(texts)
        return self._client.encode(texts)

    def embed_query(self, text: str) -> list[float]:
        if self._client is None:
            return [0.0]
        return self._client.encode([text])[0]

    async def aembed_documents(self, texts: list[str]) -> list[list[float]]:
        if self._client is None:
            return [[0.0]] * len(texts)
        return await self._client.aencode(texts)

    async def aembed_query(self, text: str) -> list[float]:
        if self._client is None:
            return [0.0]
        result = await self._client.aencode([text])
        return result[0]


def _create_embeddings():
    """根据配置创建 Embedding 实例，使用子进程隔离避免 segfault"""
    import os
    if os.environ.get("DISABLE_LOCAL_EMBEDDINGS") == "1":
        return None
    if "deepseek" in settings.openai_base_url:
        return _SubprocessEmbeddings()
    return OpenAIEmbeddings(
        model=settings.embedding_model,
        api_key=settings.openai_api_key,
        base_url=settings.openai_base_url,
    )


class VectorStoreService:
    """向量库统一接口，底层可切换 ChromaDB / PGVector"""

    COLLECTION_NAME = "knowledge_chunks"

    def __init__(self) -> None:
        self._embeddings: Any = None
        self._store: Any = None
        self._backend = settings.vector_store_type
        from concurrent.futures import ThreadPoolExecutor
        self._executor = ThreadPoolExecutor(max_workers=2)
        self._lexical_docs: dict[str, dict[str, Any]] = {}
        self._lexical_index_path = os.path.abspath(
            os.path.join(settings.upload_dir, "..", "chroma_data", "lexical_index.json")
        )

    async def _run_sync(self, fn, *args, **kwargs):
        """Run chromadb operations in thread pool to avoid async segfaults."""
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, lambda: fn(*args, **kwargs))

    @property
    def embeddings(self):
        if self._embeddings is None:
            import os
            # Skip HuggingFace embedding model if it causes instability
            # Use DISABLE_LOCAL_EMBEDDINGS=1 to force LLM-only mode
            if os.environ.get("DISABLE_LOCAL_EMBEDDINGS") == "1":
                return None
            try:
                self._embeddings = _create_embeddings()
            except Exception:
                self._embeddings = None
        return self._embeddings

    @property
    def embeddings_available(self) -> bool:
        import os
        if os.environ.get("DISABLE_LOCAL_EMBEDDINGS") == "1":
            return False
        if self._embeddings is not None:
            return True
        # Try loading; if it fails, stay disabled
        try:
            return self.embeddings is not None
        except Exception:
            return False

    # ── initialization ───────────────────────────────────────

    async def init(self) -> None:
        self._load_lexical_index()
        if self._backend == "chroma":
            await self._init_chroma()
        else:
            await self._init_pgvector()

    async def _init_chroma(self) -> None:
        def _init():
            import chromadb
            import os
            persist_dir = os.path.join(settings.upload_dir, "..", "chroma_data")
            os.makedirs(persist_dir, exist_ok=True)
            client = chromadb.PersistentClient(path=persist_dir)
            return client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
        self._store = await self._run_sync(_init)

    async def _init_pgvector(self) -> None:
        from langchain_community.vectorstores import PGVector
        self._store = PGVector(
            connection_string=settings.pgvector_dsn,
            collection_name=self.COLLECTION_NAME,
            embedding_function=self.embeddings,
        )

    # ── CRUD ─────────────────────────────────────────────────

    async def add_chunks(self, chunks: list[DocumentChunk]) -> int:
        """写入持久化词法索引，并在可用时同步写入向量后端。"""
        if not chunks:
            return 0

        for chunk in chunks:
            self._lexical_docs[chunk.chunk_id] = {
                "content": chunk.content,
                "source": chunk.metadata.get("source", ""),
                "doc_id": chunk.doc_id,
                "metadata": {**chunk.metadata, "doc_type": chunk.doc_type.value},
            }
        self._save_lexical_index()

        if self.embeddings_available and self._store is not None:
            texts = [chunk.content for chunk in chunks]
            embeddings = await self.embeddings.aembed_documents(texts)
            ids = [chunk.chunk_id for chunk in chunks]
            metadatas = [
                {
                    "doc_id": chunk.doc_id,
                    "source": str(chunk.metadata.get("source", "")),
                    "chunk_index": chunk.chunk_index,
                    "doc_type": chunk.doc_type.value,
                }
                for chunk in chunks
            ]
            if self._backend == "chroma":
                await self._run_sync(
                    self._store.upsert,
                    ids=ids,
                    documents=texts,
                    embeddings=embeddings,
                    metadatas=metadatas,
                )
            else:
                from langchain_core.documents import Document
                documents = [Document(page_content=t, metadata=m) for t, m in zip(texts, metadatas)]
                await self._store.aadd_documents(documents, ids=ids)
        return len(chunks)

    async def search(self, query: str, top_k: int = 5) -> list[tuple[dict, float]]:
        """优先使用语义检索；无模型时自动回退到可解释的本地词法检索。"""
        if self.embeddings_available and self._store is not None:
            if self._backend == "chroma":
                query_embedding = await self.embeddings.aembed_query(query)
                result = await self._run_sync(
                    self._store.query,
                    query_embeddings=[query_embedding],
                    n_results=top_k,
                    include=["documents", "metadatas", "distances"],
                )
                documents = result.get("documents", [[]])[0]
                metadatas = result.get("metadatas", [[]])[0]
                distances = result.get("distances", [[]])[0]
                return [
                    (
                        {"content": content, "source": meta.get("source", ""), "metadata": meta},
                        max(0.0, min(1.0, 1.0 - float(distance))),
                    )
                    for content, meta, distance in zip(documents, metadatas, distances)
                ]
            results = await self._store.asimilarity_search_with_score(query, k=top_k)
            return [
                ({"content": doc.page_content, "source": doc.metadata.get("source", ""), "metadata": doc.metadata}, max(0.0, 1.0 - float(score)))
                for doc, score in results
            ]
        return self._lexical_search(query, top_k)

    async def delete_by_doc_id(self, doc_id: str) -> int:
        """按 doc_id 删除所有相关向量"""
        lexical_ids = [key for key, doc in self._lexical_docs.items() if doc.get("doc_id") == doc_id]
        for key in lexical_ids:
            self._lexical_docs.pop(key, None)
        if lexical_ids:
            self._save_lexical_index()

        if self._backend == "chroma" and self._store is not None:
            existing = await self._run_sync(self._store.get, where={"doc_id": doc_id}, include=[])
            ids = existing.get("ids", [])
            if ids:
                await self._run_sync(self._store.delete, ids=ids)
            return max(len(ids), len(lexical_ids))
        return len(lexical_ids)

    async def get_stats(self) -> dict:
        """获取持久化索引统计信息。"""
        if self._backend == "chroma":
            return {
                "backend": "chroma+lexical",
                "total_vectors": len(self._lexical_docs),
                "collection": self.COLLECTION_NAME,
                "semantic_enabled": self.embeddings_available,
            }
        return {"backend": "pgvector", "collection": self.COLLECTION_NAME}

    # ── Offline lexical fallback ─────────────────────────────

    @staticmethod
    def _terms(text: str) -> set[str]:
        lowered = text.lower()
        words = set(re.findall(r"[a-z0-9_.:/-]{2,}|[\u4e00-\u9fff]", lowered))
        chinese = "".join(re.findall(r"[\u4e00-\u9fff]", lowered))
        words.update(chinese[i : i + 2] for i in range(max(0, len(chinese) - 1)))
        return {word for word in words if word}

    def _lexical_search(self, query: str, top_k: int) -> list[tuple[dict, float]]:
        query_terms = self._terms(query)
        if not query_terms:
            return []
        ranked: list[tuple[dict, float]] = []
        for doc in self._lexical_docs.values():
            doc_terms = self._terms(doc.get("content", ""))
            overlap = len(query_terms & doc_terms)
            if overlap == 0:
                continue
            recall = overlap / len(query_terms)
            precision = overlap / max(len(doc_terms), 1)
            score = min(1.0, 0.85 * recall + 0.15 * precision)
            ranked.append(({**doc, "retrieval_type": "lexical"}, score))
        ranked.sort(key=lambda item: item[1], reverse=True)
        return ranked[:top_k]

    def _load_lexical_index(self) -> None:
        try:
            with open(self._lexical_index_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                self._lexical_docs = data
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self._lexical_docs = {}

    def _save_lexical_index(self) -> None:
        os.makedirs(os.path.dirname(self._lexical_index_path), exist_ok=True)
        temp_path = f"{self._lexical_index_path}.tmp"
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(self._lexical_docs, handle, ensure_ascii=False)
        os.replace(temp_path, self._lexical_index_path)

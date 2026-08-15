"""
FastAPI 入口 — SentinelKB AI 安全知识中枢 REST API

提供三组接口:
  1. /api/ingest   — 文档上传 & 入库
  2. /api/qa       — 智能问答
  3. /api/admin    — 管理（统计、更新触发）
"""

from __future__ import annotations

import os
import re
import secrets
import logging
import hashlib
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agents.doc_parser_agent import DocParserAgent
from agents.knowledge_extract_agent import KnowledgeExtractAgent
from agents.knowledge_update_agent import ChangeType, DocumentChange, KnowledgeUpdateAgent
from agents.qa_agent import QAAgent
from agents.security_analysis_agent import SecurityAnalysisAgent
from config import settings
from orchestrator.graph import build_knowledge_graph_workflow
from services.knowledge_graph import KnowledgeGraphService
from services.vector_store import VectorStoreService

vector_store = VectorStoreService()
knowledge_graph = KnowledgeGraphService()
security_agent = SecurityAnalysisAgent()
workflows: dict[str, Any] = {}
runtime_status: dict[str, dict[str, str | None]] = {
    "llm": {"status": "not_started", "detail": None},
    "vector_store": {"status": "not_started", "detail": None},
    "knowledge_graph": {"status": "not_started", "detail": None},
    "workflows": {"status": "not_started", "detail": None},
}
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(settings.upload_dir, exist_ok=True)
    runtime_status["llm"] = {
        "status": "ready" if settings.llm_configured else "disabled",
        "detail": None if settings.llm_configured else "No non-placeholder API key; offline mode enabled",
    }
    runtime_status["vector_store"] = {"status": "starting", "detail": None}
    try:
        await vector_store.init()
        runtime_status["vector_store"] = {"status": "ready", "detail": None}
    except Exception as exc:
        runtime_status["vector_store"] = {
            "status": "unavailable",
            "detail": f"{type(exc).__name__}: {exc}",
        }
        logger.warning(
            "Vector store unavailable; lexical fallback may remain available: %s",
            exc,
        )

    runtime_status["knowledge_graph"] = {"status": "starting", "detail": None}
    try:
        await knowledge_graph.init()
        runtime_status["knowledge_graph"] = {"status": "ready", "detail": None}
    except Exception as exc:
        runtime_status["knowledge_graph"] = {
            "status": "unavailable",
            "detail": f"{type(exc).__name__}: {exc}",
        }
        logger.warning("Knowledge graph unavailable; graph retrieval is disabled: %s", exc)

    try:
        workflows.update(
            build_knowledge_graph_workflow(vector_store=vector_store, knowledge_graph=knowledge_graph)
        )
        runtime_status["workflows"] = {"status": "ready", "detail": None}
    except Exception as exc:
        runtime_status["workflows"] = {
            "status": "unavailable",
            "detail": f"{type(exc).__name__}: {exc}",
        }
        logger.warning("Workflows unavailable: %s", exc)
    yield
    try:
        await knowledge_graph.close()
    except Exception:
        logger.exception("Knowledge graph shutdown failed")


app = FastAPI(
    title="SentinelKB — AI 安全知识中枢",
    description="融合私有安全知识库、GraphRAG、IOC 识别与 ATT&CK 映射的安全运营 Copilot",
    version="2.0.0",
    lifespan=lifespan,
)

# ── Static Files & Frontend ──────────────────────────────────

static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def serve_frontend():
    from fastapi.responses import FileResponse
    return FileResponse(
        os.path.join(static_dir, "index.html"),
        headers={"Cache-Control": "no-store"},
    )


# ── Request / Response Models ────────────────────────────────

class QuestionRequest(BaseModel):
    question: str


class QuestionResponse(BaseModel):
    question: str
    answer: str
    confidence: float
    intent: str
    sources: list[dict[str, Any]]
    reasoning_steps: list[str]


class IngestResponse(BaseModel):
    document_id: str
    file_name: str
    chunks_count: int
    entities_count: int
    relations_count: int
    security_risk: str
    ioc_count: int
    attack_technique_count: int
    extraction_mode: str
    vectors_stored: int
    entities_stored: int
    relations_stored: int
    status: str
    duplicate: bool = False
    message: str = ""


class StatsResponse(BaseModel):
    vector_store: dict[str, Any]
    knowledge_graph: dict[str, Any]
    security: dict[str, Any]


class SecurityAnalysisRequest(BaseModel):
    text: str
    source: str = "manual"


class SecurityAnalysisResponse(BaseModel):
    risk_score: int
    severity: str
    indicators: list[dict[str, Any]]
    techniques: list[dict[str, Any]]
    recommendations: list[str]
    summary: str
    source: str


class UpdateRequest(BaseModel):
    file_path: str
    change_type: str = "modified"


class UpdateResponse(BaseModel):
    file_path: str
    vectors_added: int
    vectors_deleted: int
    entities_added: int
    relations_added: int
    success: bool
    processing_time_ms: float


# ── Ingest Endpoints ─────────────────────────────────────────

ALLOWED_UPLOAD_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".csv", ".xlsx", ".xls", ".txt", ".md"}
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


async def _save_upload_safely(file: UploadFile) -> tuple[str, str, str]:
    """使用白名单、大小限制和随机前缀保存文件，阻断路径穿越与覆盖。"""
    original_name = Path(file.filename or "unknown").name
    original_name = re.sub(r"[^\w.\- ()\u4e00-\u9fff]", "_", original_name)[:160]
    suffix = Path(original_name).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"不支持的文件类型: {suffix or '无扩展名'}")

    stored_name = f"{secrets.token_hex(4)}_{original_name}"
    save_path = Path(settings.upload_dir).resolve() / stored_name
    written = 0
    digest = hashlib.sha256()
    try:
        with save_path.open("wb") as destination:
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="文件不能超过 25 MB")
                digest.update(chunk)
                destination.write(chunk)
    except Exception:
        save_path.unlink(missing_ok=True)
        raise
    finally:
        await file.close()
    return str(save_path), original_name, digest.hexdigest()[:16]

@app.post("/api/ingest/upload", response_model=IngestResponse, tags=["文档入库"])
async def upload_document(file: UploadFile = File(...)):
    """上传并解析文档，自动入库到向量库和知识图谱"""
    save_path, original_name, document_id = await _save_upload_safely(file)

    if vector_store.has_doc_id(document_id):
        Path(save_path).unlink(missing_ok=True)
        return IngestResponse(
            document_id=document_id,
            file_name=original_name,
            chunks_count=vector_store.count_chunks_by_doc_id(document_id),
            entities_count=0,
            relations_count=0,
            security_risk="unchanged",
            ioc_count=0,
            attack_technique_count=0,
            extraction_mode="not_repeated",
            vectors_stored=0,
            entities_stored=0,
            relations_stored=0,
            status="duplicate",
            duplicate=True,
            message="相同内容已存在，未重复解析或写入。",
        )

    ingest_wf = workflows.get("ingest")
    if not ingest_wf:
        raise HTTPException(status_code=503, detail="Ingest workflow not initialized")

    try:
        result = await ingest_wf.ainvoke({
            "file_paths": [save_path],
            "source_names": {save_path: original_name},
        })
    except Exception as exc:
        Path(save_path).unlink(missing_ok=True)
        logger.exception("Document ingestion failed before storage completed")
        raise HTTPException(
            status_code=502,
            detail=f"文档解析或知识抽取失败（{type(exc).__name__}）。",
        ) from exc
    storage_errors = [
        message for message in (
            result.get("vector_store_error"),
            result.get("knowledge_graph_error"),
        ) if message
    ]
    if storage_errors:
        Path(save_path).unlink(missing_ok=True)
        raise HTTPException(status_code=503, detail={
            "message": "文档已解析，但知识存储失败",
            "errors": storage_errors,
        })
    chunks = result.get("chunks", [])
    extractions = result.get("extractions", [])
    total_entities = sum(len(e.entities) for e in extractions)
    total_relations = sum(len(e.relations) for e in extractions)
    security_result = await security_agent.analyze(
        "\n".join(chunk.content for chunk in chunks),
        source=original_name,
    )

    return IngestResponse(
        document_id=document_id,
        file_name=original_name,
        chunks_count=len(chunks),
        entities_count=total_entities,
        relations_count=total_relations,
        security_risk=security_result.severity,
        ioc_count=len(security_result.indicators),
        attack_technique_count=len(security_result.techniques),
        extraction_mode=result.get("extraction_status", "unknown"),
        vectors_stored=result.get("vectors_stored", 0),
        entities_stored=result.get("entities_stored", 0),
        relations_stored=result.get("relations_stored", 0),
        status="success",
        duplicate=False,
        message="文档解析、索引和知识图谱写入完成。",
    )


@app.post("/api/ingest/batch", response_model=list[IngestResponse], tags=["文档入库"])
async def upload_batch(files: list[UploadFile] = File(...)):
    """批量上传文档"""
    results = []
    for file in files:
        resp = await upload_document(file)
        results.append(resp)
    return results


# ── QA Endpoints ─────────────────────────────────────────────

@app.post("/api/qa/ask", response_model=QuestionResponse, tags=["智能问答"])
async def ask_question(req: QuestionRequest):
    """智能问答 — 混合检索 + 知识图谱推理"""
    qa_wf = workflows.get("qa")
    if not qa_wf:
        raise HTTPException(status_code=503, detail="QA workflow not initialized")

    try:
        result = await qa_wf.ainvoke({"question": req.question})
    except Exception as exc:
        logger.exception("Online QA request failed")
        raise HTTPException(
            status_code=502,
            detail=f"模型服务调用失败（{type(exc).__name__}）。请稍后重试或切换离线模式。",
        ) from exc
    qa_result = result.get("result")
    if not qa_result:
        raise HTTPException(status_code=500, detail="QA failed")

    return QuestionResponse(
        question=qa_result.question,
        answer=qa_result.answer,
        confidence=qa_result.confidence,
        intent=qa_result.intent.value,
        sources=[
            {"content": c.content[:200], "source": c.source, "score": c.score, "type": c.retrieval_type}
            for c in qa_result.contexts
        ],
        reasoning_steps=qa_result.reasoning_steps,
    )


# ── Security Analysis Endpoints ─────────────────────────────

@app.post("/api/security/analyze", response_model=SecurityAnalysisResponse, tags=["安全研判"])
async def analyze_security_event(req: SecurityAnalysisRequest):
    """对告警或事件文本提取 IOC、映射 ATT&CK 并给出处置优先级。"""
    try:
        result = await security_agent.analyze(req.text, req.source)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return SecurityAnalysisResponse(**result.to_dict())


# ── Admin Endpoints ──────────────────────────────────────────

@app.get("/api/admin/stats", response_model=StatsResponse, tags=["系统管理"])
async def get_stats():
    """获取系统统计信息"""
    try:
        vs_stats = await vector_store.get_stats()
    except Exception:
        vs_stats = {"backend": "chroma", "total_vectors": 0}
    try:
        kg_stats = await knowledge_graph.get_stats()
    except Exception:
        kg_stats = {"total_entities": 0, "total_relations": 0}
    return StatsResponse(
        vector_store=vs_stats,
        knowledge_graph=kg_stats,
        security=security_agent.get_stats(),
    )


@app.post("/api/admin/update", response_model=UpdateResponse, tags=["系统管理"])
async def trigger_update(req: UpdateRequest):
    """手动触发知识更新"""
    update_wf = workflows.get("update")
    if not update_wf:
        raise HTTPException(status_code=503, detail="Update workflow not initialized")

    change = DocumentChange(
        file_path=req.file_path,
        change_type=ChangeType(req.change_type),
    )
    result = await update_wf.ainvoke({"changes": [change]})
    results = result.get("results", [])
    if not results:
        raise HTTPException(status_code=500, detail="Update failed")

    r = results[0]
    return UpdateResponse(
        file_path=r.change.file_path,
        vectors_added=r.vectors_added,
        vectors_deleted=r.vectors_deleted,
        entities_added=r.entities_added,
        relations_added=r.relations_added,
        success=r.success,
        processing_time_ms=r.processing_time_ms,
    )


@app.get("/api/health", tags=["系统管理"])
async def health():
    statuses = {name: item["status"] for name, item in runtime_status.items()}
    required = ("vector_store", "knowledge_graph", "workflows")
    overall = "ok" if all(statuses[name] == "ready" for name in required) else "degraded"
    return {
        "status": overall,
        "mode": "online" if statuses["llm"] == "ready" else "offline",
        "service": "SentinelKB",
        "version": "2.0.0",
        "components": runtime_status,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host=settings.api_host, port=settings.api_port, reload=True)

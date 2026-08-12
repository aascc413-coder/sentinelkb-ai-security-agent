from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
from pathlib import Path

from agents.doc_parser_agent import DocParserAgent
from evaluation.retrieval import RetrievalCaseResult, mean_reciprocal_rank, recall_at_k
from services.vector_store import VectorStoreService


async def evaluate(data_dir: Path, top_k: int) -> dict:
    os.environ["DISABLE_LOCAL_EMBEDDINGS"] = "1"
    parser = DocParserAgent()
    store = VectorStoreService()

    with tempfile.TemporaryDirectory(prefix="sentinelkb-eval-") as temp_dir:
        store._lexical_index_path = str(Path(temp_dir) / "lexical_index.json")
        for document_path in sorted((data_dir / "documents").glob("*.txt")):
            chunks = await parser.parse(str(document_path))
            for chunk in chunks:
                chunk.metadata["source"] = document_path.name
            await store.add_chunks(chunks)

        cases = json.loads((data_dir / "questions.json").read_text(encoding="utf-8"))
        case_results: list[RetrievalCaseResult] = []
        details = []
        for case in cases:
            matches = await store.search(case["question"], top_k=top_k)
            sources = [document.get("source", "") for document, _ in matches]
            result = RetrievalCaseResult(
                case_id=case["id"],
                retrieved_sources=sources,
                relevant_sources=set(case["relevant_sources"]),
            )
            case_results.append(result)
            details.append({
                "id": case["id"],
                "question": case["question"],
                "expected": case["relevant_sources"],
                "retrieved": sources,
                "first_relevant_rank": result.first_relevant_rank(),
            })

    return {
        "mode": "offline_lexical",
        "cases": len(case_results),
        "top_k": top_k,
        "recall_at_1": recall_at_k(case_results, 1),
        "recall_at_3": recall_at_k(case_results, min(3, top_k)),
        "mrr": mean_reciprocal_rank(case_results),
        "details": details,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="Evaluate SentinelKB offline retrieval")
    parser.add_argument("--data-dir", type=Path, default=project_root / "evals" / "data")
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = asyncio.run(evaluate(args.data_dir.resolve(), args.top_k))
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()

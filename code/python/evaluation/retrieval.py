from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RetrievalCaseResult:
    case_id: str
    retrieved_sources: list[str]
    relevant_sources: set[str]

    def first_relevant_rank(self) -> int | None:
        for rank, source in enumerate(self.retrieved_sources, start=1):
            if source in self.relevant_sources:
                return rank
        return None


def recall_at_k(results: list[RetrievalCaseResult], k: int) -> float:
    if not results:
        return 0.0
    hits = sum(
        bool(set(result.retrieved_sources[:k]) & result.relevant_sources)
        for result in results
    )
    return hits / len(results)


def mean_reciprocal_rank(results: list[RetrievalCaseResult]) -> float:
    if not results:
        return 0.0
    reciprocal_ranks = []
    for result in results:
        rank = result.first_relevant_rank()
        reciprocal_ranks.append(0.0 if rank is None else 1.0 / rank)
    return sum(reciprocal_ranks) / len(results)

from evaluation.retrieval import RetrievalCaseResult, mean_reciprocal_rank, recall_at_k


def test_retrieval_metrics_use_first_relevant_rank():
    results = [
        RetrievalCaseResult("q1", ["a.txt", "b.txt"], {"a.txt"}),
        RetrievalCaseResult("q2", ["x.txt", "b.txt"], {"b.txt"}),
        RetrievalCaseResult("q3", ["x.txt"], {"c.txt"}),
    ]

    assert recall_at_k(results, 1) == 1 / 3
    assert recall_at_k(results, 2) == 2 / 3
    assert mean_reciprocal_rank(results) == (1 + 0.5 + 0) / 3

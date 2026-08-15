from evaluation.runner import build_summary, evaluate_case, is_retryable_error, normalize, percentile


def test_evaluate_answerable_case_checks_facts_and_source():
    case = {
        "id": "case-1",
        "question": "question",
        "expected_source": "rag_test.txt",
        "required_term_groups": [["SEC-731"], ["svc_backup"]],
    }
    response = {
        "answer": "事件 SEC-731 需要禁用 svc_backup。",
        "sources": [{"source": r"D:\uploads\rag_test.txt"}],
        "confidence": 0.8,
    }

    result = evaluate_case(case, response, 123.0)

    assert result["passed"] is True
    assert result["fact_coverage"] == 1.0
    assert result["source_hit"] is True


def test_evaluate_abstention_case_detects_grounded_refusal():
    case = {"id": "unknown", "question": "经理是谁", "should_abstain": True}
    response = {"answer": "现有资料中没有提供项目经理姓名。", "sources": []}

    result = evaluate_case(case, response, 50.0)

    assert result["passed"] is True
    assert result["abstained"] is True


def test_evaluate_abstention_accepts_common_model_refusal_wording():
    case = {"id": "unknown", "question": "经理是谁", "should_abstain": True}
    response = {
        "answer": "根据提供的上下文，没有找到项目经理名字，现有资料未涉及人员信息。",
        "sources": [{"source": "rag_test.txt"}],
    }

    result = evaluate_case(case, response, 50.0)

    assert result["passed"] is True
    assert result["abstained"] is True


def test_summary_and_text_normalization_are_deterministic():
    results = [
        {"passed": True, "should_abstain": False, "fact_coverage": 1.0, "source_hit": True, "abstained": False, "latency_ms": 100.0},
        {"passed": True, "should_abstain": True, "fact_coverage": 1.0, "source_hit": True, "abstained": True, "latency_ms": 300.0},
    ]

    summary = build_summary(results, 400.0)

    assert normalize(" SEC-731 \n") == "sec-731"
    assert percentile([100.0, 300.0], 0.95) == 300.0
    assert summary["pass_rate"] == 1.0
    assert summary["abstention_accuracy"] == 1.0


def test_rate_limit_and_gateway_errors_are_retryable():
    assert is_retryable_error(RuntimeError("RateLimitError")) is True
    assert is_retryable_error(RuntimeError("HTTP 502")) is True
    assert is_retryable_error(ValueError("invalid dataset")) is False

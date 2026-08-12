from config.settings import Settings


def test_offline_embedding_flag_is_a_supported_setting(monkeypatch):
    monkeypatch.setenv("DISABLE_LOCAL_EMBEDDINGS", "1")

    configured = Settings(_env_file=None)

    assert configured.disable_local_embeddings is True


def test_placeholder_key_does_not_enable_online_mode(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-your-api-key-here")

    configured = Settings(_env_file=None)

    assert configured.llm_configured is False


def test_real_key_requires_explicit_llm_enable_switch():
    configured = Settings(
        openai_api_key="sk-test-only",
        enable_llm=False,
        _env_file=None,
    )
    assert configured.llm_configured is False

    enabled = Settings(
        openai_api_key="sk-test-only",
        enable_llm=True,
        _env_file=None,
    )
    assert enabled.llm_configured is True

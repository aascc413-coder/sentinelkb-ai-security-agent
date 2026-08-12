"""
应用配置 — 通过环境变量或 .env 文件加载
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # LLM
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o"
    embedding_model: str = "text-embedding-3-small"
    enable_llm: bool = False
    disable_local_embeddings: bool = True

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"

    # Vector Store
    vector_store_type: str = "chroma"  # chroma | pgvector
    chroma_host: str = "localhost"
    chroma_port: int = 8000
    pgvector_dsn: str = "postgresql://postgres:postgres@localhost:5432/knowledge"

    # Kafka (CDC)
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_doc_changes: str = "doc-changes"
    kafka_topic_kg_updates: str = "kg-updates"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8080

    # Document Store
    upload_dir: str = "./uploads"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @property
    def llm_configured(self) -> bool:
        """Whether a non-placeholder model credential is available."""
        key = self.openai_api_key.strip()
        placeholders = {"sk-your-api-key-here", "your-api-key", "changeme"}
        return self.enable_llm and bool(key) and key.lower() not in placeholders


settings = Settings()

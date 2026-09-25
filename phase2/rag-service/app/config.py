from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    app_name: str = "Security Knowledge Graph RAG"
    app_version: str = "1.0.0"
    app_port: int = 8092

    neo4j_uri: str
    neo4j_username: str
    neo4j_password: str
    neo4j_database: str = "neo4j"

    ollama_url: str
    ollama_model: str = "qwen3"
    ollama_timeout: int = 120

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False
    )


settings = Settings()
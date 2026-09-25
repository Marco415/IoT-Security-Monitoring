import os

from dotenv import load_dotenv


load_dotenv()


NEO4J_URI = os.getenv(
    "NEO4J_URI",
    "bolt://localhost:7687"
)

NEO4J_USERNAME = os.getenv(
    "NEO4J_USERNAME",
    "neo4j"
)

NEO4J_PASSWORD = os.getenv(
    "NEO4J_PASSWORD",
    "password"
)

NEO4J_DATABASE = os.getenv(
    "NEO4J_DATABASE",
    "neo4j"
)

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://localhost:11434"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen3"
)

OLLAMA_TIMEOUT = int(
    os.getenv(
        "OLLAMA_TIMEOUT",
        "120"
    )
)
from fastapi import FastAPI

from app.router import router
from app.neo4j_client import Neo4jClient


app = FastAPI(
    title="IoT Security Monitoring - RAG API",
    description=(
        "GraphRAG service using Neo4j retrieval "
        "and Qwen3 generation."
    ),
    version="1.0.0"
)


app.include_router(
    router
)


@app.get("/")
def root():

    return {
        "service": "rag-service",
        "status": "running",
        "port": 8092
    }


@app.get("/health")
def health():

    neo4j = Neo4jClient()

    try:

        connected = (
            neo4j.verify_connection()
        )

        return {
            "status": "UP",
            "neo4j": (
                "UP"
                if connected
                else "DOWN"
            )
        }

    except Exception as exc:

        return {
            "status": "DOWN",
            "neo4j": "DOWN",
            "error": str(exc)
        }

    finally:

        neo4j.close()
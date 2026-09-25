from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from .config import settings
from .models import RAGRequest, RAGResponse
from .neo4j_client import neo4j_client
from .ollama_client import ollama_client
from .prompt_builder import (
    build_evidence,
    evidence_to_text,
    build_prompt
)
from .retrieval import retrieve
from .router import query_router


@asynccontextmanager
async def lifespan(app: FastAPI):

    print("Starting RAG service...")

    if neo4j_client.verify_connection():

        print("Neo4j connection successful.")

    else:

        print("WARNING: Neo4j connection failed.")

    yield

    neo4j_client.close()

    print("RAG service stopped.")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Cypher-Based GraphRAG service for the "
        "IoT Security Monitoring System."
    ),
    lifespan=lifespan
)


@app.get("/")
def root():

    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "running"
    }


@app.get("/health")
def health():

    neo4j_ok = neo4j_client.verify_connection()

    return {
        "status": "UP" if neo4j_ok else "DEGRADED",
        "neo4j": neo4j_ok,
        "ollama": settings.ollama_url,
        "model": settings.ollama_model
    }


@app.post(
    "/api/rag/ask",
    response_model=RAGResponse
)
async def ask_question(
    request: RAGRequest
):

    question = request.question.strip()

    if not question:

        raise HTTPException(
            status_code=400,
            detail="Question cannot be empty."
        )

    intent = query_router.classify(
        question
    )

    try:

        graph_results = retrieve(
            intent,
            question
        )

    except Exception as exc:

        raise HTTPException(
            status_code=503,
            detail=f"Neo4j retrieval failed: {exc}"
        )

    evidence = build_evidence(
        graph_results
    )

    evidence_text = evidence_to_text(
        evidence
    )

    if not evidence["nodes"]:

        answer = (
            "The knowledge graph does not contain "
            "enough information to answer this question."
        )

        return RAGResponse(
            question=question,
            intent=intent,
            answer=answer,
            retrieval_method=(
                "Controlled Cypher query against Neo4j"
            ),
            evidence_nodes=[],
            evidence_relationships=[],
            evidence_summary=evidence_text
        )

    prompt = build_prompt(
        question,
        evidence_text
    )

    try:

        answer = await ollama_client.generate(
            prompt
        )

    except Exception as exc:

        raise HTTPException(
            status_code=503,
            detail=f"Ollama generation failed: {exc}"
        )

    return RAGResponse(
        question=question,
        intent=intent,
        answer=answer,
        retrieval_method=(
            "Controlled Cypher query → Neo4j graph "
            "retrieval → Qwen3 answer generation"
        ),
        evidence_nodes=evidence["nodes"],
        evidence_relationships=evidence["relationships"],
        evidence_summary=evidence_text
    )
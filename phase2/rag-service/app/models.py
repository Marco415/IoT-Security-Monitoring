from typing import List

from pydantic import BaseModel, Field


class RAGRequest(BaseModel):
    question: str = Field(
        ...,
        min_length=3,
        description="Natural-language question to ask the RAG system."
    )


class EvidenceNode(BaseModel):
    id: str
    label: str
    name: str | None = None
    properties: dict = Field(default_factory=dict)


class EvidenceRelationship(BaseModel):
    source: str
    relationship: str
    target: str


class RAGResponse(BaseModel):
    question: str
    intent: str
    answer: str

    retrieval_method: str

    evidence_nodes: List[EvidenceNode] = Field(
        default_factory=list
    )

    evidence_relationships: List[EvidenceRelationship] = Field(
        default_factory=list
    )

    evidence_count: int

    grounding: str

    evidence_summary: str
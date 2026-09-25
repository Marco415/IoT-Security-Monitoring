from typing import Any

from pydantic import BaseModel, Field


class RAGRequest(BaseModel):
    question: str = Field(
        ...,
        min_length=3,
        description="Natural-language security question"
    )


class EvidenceNode(BaseModel):
    label: str
    properties: dict[str, Any]


class EvidenceRelationship(BaseModel):
    source: str
    relationship: str
    target: str


class RAGResponse(BaseModel):
    question: str
    intent: str
    answer: str

    retrieval_method: str

    evidence_nodes: list[EvidenceNode]
    evidence_relationships: list[EvidenceRelationship]

    evidence_summary: str
import re

from fastapi import APIRouter, HTTPException

from app.models import (
    RAGRequest,
    RAGResponse,
    EvidenceNode,
    EvidenceRelationship,
)

from app.neo4j_client import Neo4jClient
from app.retrieval import GraphRetriever
from app.prompt_builder import PromptBuilder
from app.ollama_client import OllamaClient


router = APIRouter(
    prefix="/api/rag",
    tags=["RAG"]
)


neo4j_client = Neo4jClient()

retriever = GraphRetriever(
    neo4j_client
)

ollama = OllamaClient()


# ============================================================
# INTENT DETECTION
# ============================================================

def detect_intent(
    question: str
) -> str:

    q = question.lower()

    if "alert-001" in q:

        if (
            "control" in q
            or "mitigate" in q
        ):
            return "threat_controls"

        return "alert_investigation"

    if (
        "service" in q
        and (
            "affected" in q
            or "fails" in q
            or "fail" in q
            or "dependency" in q
        )
    ):
        return "service_dependencies"

    return "security_overview"


# ============================================================
# ID EXTRACTION
# ============================================================

def extract_alert_id(
    question: str
):

    match = re.search(
        r"alert-\d+",
        question.lower()
    )

    if match:
        return match.group(0)

    return None


def extract_service_name(
    question: str
):

    services = [
        "event-service",
        "device-service",
        "auth-service",
        "gateway",
        "soc-service",
        "rag-service",
    ]

    q = question.lower()

    for service in services:

        if service in q:
            return service

    return None


# ============================================================
# NEO4J NODE CONVERSION
# ============================================================

def convert_node(node):
    """
    Convert a Neo4j Node or dictionary into the normalized
    EvidenceNode format expected by the RAG API.

    Output format:

        {
            "id": "...",
            "label": "...",
            "properties": {...}
        }
    """

    if node is None:
        return None

    # =========================================================
    # DICTIONARY
    # =========================================================

    if isinstance(node, dict):

        labels = node.get(
            "labels",
            []
        )

        properties = node.get(
            "properties",
            {}
        )

        # If this is a plain property dictionary,
        # treat all fields as properties.
        if not properties:

            properties = {
                key: value
                for key, value in node.items()
                if key not in {
                    "id",
                    "label",
                    "labels",
                }
            }

        # Normalize labels.
        if isinstance(labels, str):

            label = labels

        elif labels:

            label = str(
                labels[0]
            )

        else:

            # Some Neo4j conversion paths may not preserve
            # labels. Fall back to the most useful identifier.
            label = (
                node.get("label")
                or "Node"
            )

        # Stable business identifier.
        node_id = (
            node.get("id")
            or properties.get("alertId")
            or properties.get("eventId")
            or properties.get("userId")
            or properties.get("name")
        )

        return {
            "id": (
                str(node_id)
                if node_id is not None
                else None
            ),
            "label": label,
            "properties": properties,
        }

    # =========================================================
    # NATIVE NEO4J NODE
    # =========================================================

    labels = list(
        node.labels
    )

    properties = dict(
        node
    )

    node_id = (
        properties.get("alertId")
        or properties.get("eventId")
        or properties.get("userId")
        or properties.get("name")
        or str(node.id)
    )

    label = (
        str(labels[0])
        if labels
        else "Node"
    )

    return {
        "id": str(node_id),
        "label": label,
        "properties": properties,
    }


# ============================================================
# RELATIONSHIP CONVERSION
# ============================================================

def convert_relationship(
    relationship
):

    if not relationship:
        return None

    source = relationship.get(
        "source"
    )

    target = relationship.get(
        "target"
    )

    relation = relationship.get(
        "relationship"
    )

    if not source or not target:
        return None

    return EvidenceRelationship(
        source=str(source),
        relationship=str(relation),
        target=str(target)
    )


# ============================================================
# ALERT EVIDENCE
# ============================================================

def build_alert_evidence(
    records
):

    nodes = []
    relationships = []

    node_ids = set()
    relationship_ids = set()

    for record in records:

        candidates = []

        if record.get("alert"):
            candidates.append(
                record["alert"]
            )

        candidates.extend(
            record.get(
                "events",
                []
            )
        )

        candidates.extend(
            record.get(
                "users",
                []
            )
        )

        candidates.extend(
            record.get(
                "threats",
                []
            )
        )

        candidates.extend(
            record.get(
                "controls",
                []
            )
        )

        for item in candidates:

            if not item:
                continue

            node = convert_node(item)

            if node:
                node_id = node.get("id")

                if node_id and node_id not in node_ids:
                    node_ids.add(node_id)
                    nodes.append(node)

        relationship_groups = [
            record.get(
                "event_alert_relationships",
                []
            ),
            record.get(
                "user_event_relationships",
                []
            ),
            record.get(
                "alert_threat_relationships",
                []
            ),
            record.get(
                "control_threat_relationships",
                []
            ),
        ]

        for group in relationship_groups:

            for item in group:

                relationship = (
                    convert_relationship(item)
                )

                if not relationship:
                    continue

                key = (
                    relationship.source,
                    relationship.relationship,
                    relationship.target
                )

                if key not in relationship_ids:

                    relationships.append(
                        relationship
                    )

                    relationship_ids.add(
                        key
                    )

    return nodes, relationships


# ============================================================
# CONTROL EVIDENCE
# ============================================================

def build_control_evidence(
    records
):

    nodes = []
    relationships = []

    node_ids = set()
    relationship_ids = set()

    for record in records:

        for key in [
            "alert",
            "threat",
        ]:

            item = record.get(key)

            if item:

                node = convert_node(item)

                if node:

                    node_id = node.get("id")

                    if (
                        node_id
                        and node_id not in node_ids
                    ):

                        nodes.append(node)
                        node_ids.add(node_id)

        for control in record.get(
            "controls",
            []
        ):

            if control:

                node = convert_node(
                    control
                )

                if node:

                    node_id = node.get("id")

                    if (
                        node_id
                        and node_id not in node_ids
                    ):

                        nodes.append(node)
                        node_ids.add(node_id)

        for group_name in [
            "alert_threat_relationships",
            "control_threat_relationships",
        ]:

            for item in record.get(
                group_name,
                []
            ):

                relationship = (
                    convert_relationship(item)
                )

                if not relationship:
                    continue

                key = (
                    relationship.source,
                    relationship.relationship,
                    relationship.target
                )

                if key not in relationship_ids:

                    relationships.append(
                        relationship
                    )

                    relationship_ids.add(
                        key
                    )

    return nodes, relationships


# ============================================================
# SERVICE EVIDENCE
# ============================================================

def build_service_evidence(
    records
):

    nodes = []
    relationships = []

    node_ids = set()
    relationship_ids = set()

    for record in records:

        failed = record.get(
            "failed"
        )

        if failed:

            node = convert_node(
                failed
            )

            if node:

                node_id = node.get("id")

                if (
                    node_id
                    and node_id not in node_ids
                ):

                    nodes.append(node)
                    node_ids.add(node_id)

        for affected in record.get(
            "affected_services",
            []
        ):

            if affected:

                node = convert_node(
                    affected
                )

                if node:

                    node_id = node.get("id")

                    if (
                        node_id
                        and node_id not in node_ids
                    ):

                        nodes.append(node)
                        node_ids.add(node_id)

        for item in record.get(
            "dependency_relationships",
            []
        ):

            if not item:
                continue

            for relationship_data in item:

                relationship = (
                    convert_relationship(
                        relationship_data
                    )
                )

                if not relationship:
                    continue

                key = (
                    relationship.source,
                    relationship.relationship,
                    relationship.target
                )

                if key not in relationship_ids:

                    relationships.append(
                        relationship
                    )

                    relationship_ids.add(
                        key
                    )

    return nodes, relationships


# ============================================================
# EVIDENCE TEXT FOR QWEN3
# ============================================================

def evidence_to_text(
    nodes,
    relationships
):
    """
    Convert normalized RAG evidence into text
    for the Qwen3 prompt.
    """

    lines = []

    # =========================================================
    # NODES
    # =========================================================

    if nodes:

        lines.append(
            "NODES:"
        )

        for node in nodes:

            if not isinstance(
                node,
                dict
            ):
                continue

            node_id = node.get(
                "id"
            )

            label = node.get(
                "label",
                "Node"
            )

            properties = node.get(
                "properties",
                {}
            )

            lines.append(
                f"- {label} "
                f"(id={node_id}): "
                f"{properties}"
            )

    # =========================================================
    # RELATIONSHIPS
    # =========================================================

    if relationships:

        lines.append("")
        lines.append(
            "RELATIONSHIPS:"
        )

        for relationship in relationships:

            if isinstance(
                relationship,
                dict
            ):

                source = relationship.get(
                    "source"
                )

                relationship_type = (
                    relationship.get(
                        "relationship"
                    )
                )

                target = relationship.get(
                    "target"
                )

            else:

                source = relationship.source

                relationship_type = (
                    relationship.relationship
                )

                target = relationship.target

            lines.append(
                f"- {source} "
                f"-[{relationship_type}]-> "
                f"{target}"
            )

    if not lines:

        return (
            "No graph evidence was retrieved."
        )

    return "\n".join(lines)


# ============================================================
# SUMMARY
# ============================================================

def build_evidence_summary(
    nodes,
    relationships
):

    return (
        f"Retrieved {len(nodes)} nodes and "
        f"{len(relationships)} relationships "
        f"from the Neo4j knowledge graph."
    )


# ============================================================
# MAIN RAG ENDPOINT
# ============================================================

@router.post(
    "/ask",
    response_model=RAGResponse
)
def ask_rag(
    request: RAGRequest
):

    question = request.question.strip()

    if not question:

        raise HTTPException(
            status_code=400,
            detail="Question cannot be empty."
        )

    intent = detect_intent(
        question
    )

    # --------------------------------------------------------
    # ALERT INVESTIGATION
    # --------------------------------------------------------

    if intent == "alert_investigation":

        alert_id = extract_alert_id(
            question
        )

        if not alert_id:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Could not identify an alert ID."
                )
            )

        records = (
            retriever
            .retrieve_alert_investigation(
                alert_id
            )
        )

        nodes, relationships = (
            build_alert_evidence(
                records
            )
        )

    # --------------------------------------------------------
    # THREAT CONTROLS
    # --------------------------------------------------------

    elif intent == "threat_controls":

        alert_id = extract_alert_id(
            question
        )

        if not alert_id:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Could not identify an alert ID."
                )
            )

        records = (
            retriever
            .retrieve_threat_controls(
                alert_id
            )
        )

        nodes, relationships = (
            build_control_evidence(
                records
            )
        )

    # --------------------------------------------------------
    # SERVICE DEPENDENCIES
    # --------------------------------------------------------

    elif intent == "service_dependencies":

        service_name = (
            extract_service_name(
                question
            )
        )

        if not service_name:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Could not identify "
                    "the service name."
                )
            )

        records = (
            retriever
            .retrieve_service_dependencies(
                service_name
            )
        )

        nodes, relationships = (
            build_service_evidence(
                records
            )
        )

    else:

        raise HTTPException(
            status_code=400,
            detail=(
                "The question does not match "
                "a supported RAG retrieval intent."
            )
        )

    # --------------------------------------------------------
    # NO EVIDENCE
    # --------------------------------------------------------

    if not nodes:

        answer = (
            "The knowledge graph did not return "
            "evidence relevant to this question."
        )

        return RAGResponse(
            question=question,
            intent=intent,
            answer=answer,
            retrieval_method=(
                "Cypher graph traversal"
            ),
            evidence_nodes=[],
            evidence_relationships=[],
            evidence_count=0,
            grounding=(
                "No relevant Neo4j evidence "
                "was retrieved."
            ),
            evidence_summary=(
                "No evidence was retrieved."
            )
        )

    # --------------------------------------------------------
    # QWEN3
    # --------------------------------------------------------

    evidence_text = evidence_to_text(
        nodes,
        relationships
    )

    prompt = PromptBuilder.build(
        question=question,
        intent=intent,
        evidence=evidence_text
    )

    try:

        answer = ollama.generate(
            prompt
        )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                "Qwen3/Ollama generation failed: "
                f"{exc}"
            )
        )

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    evidence_count = (
        len(nodes)
        + len(relationships)
    )

    return RAGResponse(
        question=question,
        intent=intent,
        answer=answer,
        retrieval_method=(
            "Cypher graph traversal + Qwen3"
        ),
        evidence_nodes=nodes,
        evidence_relationships=relationships,
        evidence_count=evidence_count,
        grounding=(
            "All factual claims are based on "
            "retrieved Neo4j nodes and relationships."
        ),
        evidence_summary=(
            build_evidence_summary(
                nodes,
                relationships
            )
        )
    )
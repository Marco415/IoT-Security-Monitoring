import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.router import router
from app.neo4j_client import Neo4jClient

import py_eureka_client.eureka_client as eureka_client


# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(
    level=logging.INFO
)

logger = logging.getLogger("rag-service")


# =========================================================
# CONFIGURATION
# =========================================================

RAG_PORT = int(
    os.getenv("SERVER_PORT", "8092")
)

EUREKA_SERVER = os.getenv(
    "EUREKA_CLIENT_SERVICEURL_DEFAULTZONE",
    "http://localhost:8761/eureka/"
)


# =========================================================
# EUREKA LIFESPAN
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.info(
        "Starting RAG service on port %s",
        RAG_PORT
    )

    logger.info(
        "Registering RAG service with Eureka: %s",
        EUREKA_SERVER
    )

    try:

        await eureka_client.init_async(
            eureka_server=EUREKA_SERVER,
            app_name="rag-service",
            instance_port=RAG_PORT
        )

        logger.info(
            "RAG service successfully registered with Eureka"
        )

    except Exception as exc:

        logger.exception(
            "Failed to register RAG service with Eureka: %s",
            exc
        )

        # Do not prevent the RAG service from starting.
        # This allows /health and /docs to remain available
        # while Eureka registration is being diagnosed.

    yield

    # =====================================================
    # SHUTDOWN
    # =====================================================

    try:

        await eureka_client.stop_async()

        logger.info(
            "RAG service deregistered from Eureka"
        )

    except Exception as exc:

        logger.warning(
            "Error while stopping Eureka client: %s",
            exc
        )


# =========================================================
# FASTAPI
# =========================================================

app = FastAPI(
    title="IoT Security Monitoring - RAG API",
    description=(
        "GraphRAG service using Neo4j retrieval "
        "and Qwen3 generation."
    ),
    version="1.0.0",
    servers=[
        {
            "url": "/api/rag"
        }
    ],
    lifespan=lifespan
)


# =========================================================
# ROUTER
# =========================================================

app.include_router(
    router
)


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "service": "rag-service",
        "status": "running",
        "port": RAG_PORT
    }


# =========================================================
# HEALTH
# =========================================================

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
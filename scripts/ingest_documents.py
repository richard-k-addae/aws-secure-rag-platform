"""Ingest the synthetic corpus into a tenant.

Usage: python scripts/ingest_documents.py [tenant_id] [classification]
"""
import sys
from pathlib import Path

from app.auth.permissions import Classification
from app.rag.embeddings import EmbeddingService
from app.rag.ingestion import IngestionService
from app.rag.retrieval import VectorStore

CORPUS = Path("synthetic-data/documents")


def main() -> None:
    tenant_id = sys.argv[1] if len(sys.argv) > 1 else "tenant-a"
    classification = Classification(sys.argv[2]) if len(sys.argv) > 2 else Classification.INTERNAL
    service = IngestionService(embeddings=EmbeddingService(), store=VectorStore())
    total = 0
    for path in sorted(CORPUS.glob("*.md")):
        # Trusted operator bootstrap: explicitly skips existing-document authorization.
        count = service.ingest_file(
            path,
            tenant_id=tenant_id,
            classification=classification,
            source=path.name,
            authorize_as=None,
        )
        print(f"{path.name}: {count} chunks -> {tenant_id}/{classification.value}")
        total += count
    print(f"Done: {total} chunks ingested.")


if __name__ == "__main__":
    main()

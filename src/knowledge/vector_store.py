from __future__ import annotations

from pathlib import Path

import chromadb
import structlog

from src.config.settings import KnowledgeConfig

logger = structlog.get_logger(__name__)


class VectorStore:
    def __init__(self, config: KnowledgeConfig) -> None:
        persist_dir = Path(config.chroma_persist_dir)
        persist_dir.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=str(persist_dir))
        self.collection = self.client.get_or_create_collection(
            name=config.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        self.config = config
        logger.info(
            "vector_store_initialized",
            persist_dir=str(persist_dir),
            collection=config.collection_name,
            document_count=self.collection.count(),
        )

    def add_documents(
        self,
        ids: list[str],
        documents: list[str],
        metadatas: list[dict],
    ) -> int:
        if not ids:
            return 0
        existing = set(self.collection.get(ids=ids)["ids"])
        new_ids = []
        new_docs = []
        new_metas = []
        for i, doc_id in enumerate(ids):
            if doc_id not in existing:
                new_ids.append(doc_id)
                new_docs.append(documents[i])
                new_metas.append(metadatas[i])

        if not new_ids:
            return 0

        batch_size = 500
        added = 0
        for start in range(0, len(new_ids), batch_size):
            end = start + batch_size
            self.collection.add(
                ids=new_ids[start:end],
                documents=new_docs[start:end],
                metadatas=new_metas[start:end],
            )
            added += len(new_ids[start:end])

        logger.info("documents_added", count=added)
        return added

    def query(
        self,
        query_text: str,
        n_results: int = 10,
        metadata_filter: dict | None = None,
    ) -> list[dict]:
        if self.collection.count() == 0:
            return []

        n_results = min(n_results, self.collection.count())
        kwargs: dict = {
            "query_texts": [query_text],
            "n_results": n_results,
            "include": ["documents", "metadatas", "distances"],
        }
        if metadata_filter:
            kwargs["where"] = metadata_filter

        results = self.collection.query(**kwargs)
        return self._format_results(results)

    def get_by_metadata(
        self, metadata_filter: dict, limit: int = 10
    ) -> list[dict]:
        if self.collection.count() == 0:
            return []
        results = self.collection.get(
            where=metadata_filter,
            limit=limit,
            include=["documents", "metadatas"],
        )
        return self._format_get_results(results)

    @property
    def count(self) -> int:
        return self.collection.count()

    def _format_results(self, results: dict) -> list[dict]:
        formatted = []
        if not results["ids"] or not results["ids"][0]:
            return formatted
        for i, doc_id in enumerate(results["ids"][0]):
            distance = results["distances"][0][i] if results.get("distances") else 0.0
            score = 1.0 - distance
            formatted.append(
                {
                    "doc_id": doc_id,
                    "document": results["documents"][0][i] if results.get("documents") else "",
                    "metadata": results["metadatas"][0][i] if results.get("metadatas") else {},
                    "score": score,
                }
            )
        return formatted

    def _format_get_results(self, results: dict) -> list[dict]:
        formatted = []
        if not results["ids"]:
            return formatted
        for i, doc_id in enumerate(results["ids"]):
            formatted.append(
                {
                    "doc_id": doc_id,
                    "document": results["documents"][i] if results.get("documents") else "",
                    "metadata": results["metadatas"][i] if results.get("metadatas") else {},
                    "score": 1.0,
                }
            )
        return formatted

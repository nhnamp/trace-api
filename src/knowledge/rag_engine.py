from __future__ import annotations

import structlog
from pydantic import BaseModel

from src.config.settings import KnowledgeConfig
from src.knowledge.fusion import reciprocal_rank_fusion
from src.knowledge.keyword_search import KeywordSearch
from src.knowledge.vector_store import VectorStore

logger = structlog.get_logger(__name__)


class CVEDocument(BaseModel):
    doc_id: str
    cve_id: str
    title: str = ""
    description: str = ""
    vulnerability_type: str = ""
    affected_component: str = ""
    target_library: str | None = None
    exploit_method: str | None = None
    poc_script: str | None = None
    chain_of_thought: list[dict] | None = None
    preconditions: list[str] = []
    success_indicators: list[str] = []
    source: str = ""

    def to_embedding_text(self) -> str:
        parts = []
        if self.cve_id:
            parts.append(self.cve_id)
        if self.vulnerability_type:
            parts.append(self.vulnerability_type)
        if self.target_library:
            parts.append(f"Target: {self.target_library}")
        if self.affected_component:
            parts.append(f"Component: {self.affected_component}")
        if self.title:
            parts.append(self.title)
        if self.description:
            parts.append(self.description)
        if self.exploit_method:
            parts.append(f"Exploit: {self.exploit_method}")
        return "\n".join(parts)

    def to_metadata(self) -> dict:
        meta: dict = {"cve_id": self.cve_id, "source": self.source}
        if self.vulnerability_type:
            meta["vulnerability_type"] = self.vulnerability_type
        if self.target_library:
            meta["target_library"] = self.target_library
        if self.affected_component:
            meta["affected_component"] = self.affected_component
        return meta

    def to_context_string(self) -> str:
        parts = [f"CVE: {self.cve_id}"]
        if self.vulnerability_type:
            parts.append(f"Type: {self.vulnerability_type}")
        if self.target_library:
            parts.append(f"Target: {self.target_library}")
        if self.description:
            parts.append(f"Description: {self.description}")
        if self.exploit_method:
            parts.append(f"Exploit method: {self.exploit_method}")
        if self.chain_of_thought:
            seen: set[str] = set()
            rendered: list[str] = []
            for s in self.chain_of_thought:
                line = f"Step {s.get('step', '?')}: {s.get('action', '')} - {s.get('details', '')}"
                key = line.lower().strip()
                if key in seen:
                    continue
                seen.add(key)
                rendered.append(line)
                if len(rendered) >= 3:
                    break
            if rendered:
                parts.append("Chain of thought: " + "; ".join(rendered))
        return "\n".join(parts)


class RAGResult(BaseModel):
    doc_id: str
    cve_id: str | None = None
    content: str = ""
    score: float = 0.0
    source: str = ""
    metadata: dict = {}


class RAGEngine:
    def __init__(self, config: KnowledgeConfig) -> None:
        self.config = config
        self.vector_store = VectorStore(config)
        self.keyword_search = KeywordSearch()
        self._documents: dict[str, CVEDocument] = {}
        self.keyword_search.load(config.bm25_index_dir)

    def add_documents(self, documents: list[CVEDocument]) -> int:
        if not documents:
            return 0

        ids = []
        texts = []
        metadatas = []
        for doc in documents:
            self._documents[doc.doc_id] = doc
            ids.append(doc.doc_id)
            texts.append(doc.to_embedding_text())
            metadatas.append(doc.to_metadata())

        added = self.vector_store.add_documents(ids, texts, metadatas)
        self.keyword_search.add_documents(ids, texts)
        self.keyword_search.save(self.config.bm25_index_dir)

        logger.info("rag_documents_added", count=added, total=len(self._documents))
        return added

    def query(
        self,
        query_text: str,
        *,
        mode: str = "hybrid",
        n_results: int | None = None,
        metadata_filter: dict | None = None,
    ) -> list[RAGResult]:
        top_k = n_results or self.config.top_k

        if mode == "direct":
            return self._direct_lookup(query_text)
        elif mode == "semantic":
            return self._semantic_search(query_text, top_k, metadata_filter)
        elif mode == "keyword":
            return self._keyword_search(query_text, top_k)
        else:
            return self._hybrid_search(query_text, top_k, metadata_filter)

    def _direct_lookup(self, cve_id: str) -> list[RAGResult]:
        results = self.vector_store.get_by_metadata(
            {"cve_id": cve_id}, limit=5
        )
        return [self._to_rag_result(r) for r in results]

    def _semantic_search(
        self, query_text: str, n_results: int, metadata_filter: dict | None
    ) -> list[RAGResult]:
        results = self.vector_store.query(query_text, n_results, metadata_filter)
        return [self._to_rag_result(r) for r in results]

    def _keyword_search(self, query_text: str, n_results: int) -> list[RAGResult]:
        scored = self.keyword_search.query(query_text, n_results)
        results = []
        for doc_id, score in scored:
            doc = self._documents.get(doc_id)
            if doc:
                results.append(
                    RAGResult(
                        doc_id=doc_id,
                        cve_id=doc.cve_id,
                        content=doc.to_context_string(),
                        score=score,
                        source=doc.source,
                        metadata=doc.to_metadata(),
                    )
                )
        return results

    def _hybrid_search(
        self, query_text: str, n_results: int, metadata_filter: dict | None
    ) -> list[RAGResult]:
        fetch_k = n_results * 2

        semantic_results = self.vector_store.query(
            query_text, fetch_k, metadata_filter
        )
        semantic_ranked = [
            (r["doc_id"], r["score"]) for r in semantic_results
        ]

        keyword_ranked = self.keyword_search.query(query_text, fetch_k)

        fused = reciprocal_rank_fusion(
            [semantic_ranked, keyword_ranked], k=self.config.rrf_k
        )

        results = []
        for doc_id, score in fused[:n_results]:
            doc = self._documents.get(doc_id)
            if doc:
                results.append(
                    RAGResult(
                        doc_id=doc_id,
                        cve_id=doc.cve_id,
                        content=doc.to_context_string(),
                        score=score,
                        source=doc.source,
                        metadata=doc.to_metadata(),
                    )
                )
            else:
                sem_match = next(
                    (r for r in semantic_results if r["doc_id"] == doc_id), None
                )
                if sem_match:
                    results.append(
                        RAGResult(
                            doc_id=doc_id,
                            cve_id=sem_match["metadata"].get("cve_id"),
                            content=sem_match["document"],
                            score=score,
                            source=sem_match["metadata"].get("source", ""),
                            metadata=sem_match["metadata"],
                        )
                    )
        return results

    def _to_rag_result(self, store_result: dict) -> RAGResult:
        doc_id = store_result["doc_id"]
        doc = self._documents.get(doc_id)
        if doc:
            return RAGResult(
                doc_id=doc_id,
                cve_id=doc.cve_id,
                content=doc.to_context_string(),
                score=store_result.get("score", 0.0),
                source=doc.source,
                metadata=doc.to_metadata(),
            )
        return RAGResult(
            doc_id=doc_id,
            cve_id=store_result.get("metadata", {}).get("cve_id"),
            content=store_result.get("document", ""),
            score=store_result.get("score", 0.0),
            source=store_result.get("metadata", {}).get("source", ""),
            metadata=store_result.get("metadata", {}),
        )

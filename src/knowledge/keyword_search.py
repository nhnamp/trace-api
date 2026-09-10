from __future__ import annotations

import json
import re
from pathlib import Path

import structlog
from rank_bm25 import BM25Okapi

logger = structlog.get_logger(__name__)


def _tokenize(text: str) -> list[str]:
    text = text.lower()
    text = re.sub(r"[^\w\s\-./]", " ", text)
    tokens = text.split()
    return [t for t in tokens if len(t) > 1]


class KeywordSearch:
    def __init__(self) -> None:
        self._doc_ids: list[str] = []
        self._doc_texts: list[str] = []
        self._seen: set[str] = set()
        self._bm25: BM25Okapi | None = None

    def add_documents(self, doc_ids: list[str], texts: list[str]) -> None:
        added = False
        for doc_id, text in zip(doc_ids, texts, strict=True):
            if doc_id in self._seen:
                continue
            self._seen.add(doc_id)
            self._doc_ids.append(doc_id)
            self._doc_texts.append(text)
            added = True
        if added:
            self._rebuild_index()

    def _rebuild_index(self) -> None:
        if not self._doc_texts:
            self._bm25 = None
            return
        corpus = [_tokenize(text) for text in self._doc_texts]
        self._bm25 = BM25Okapi(corpus)
        if hasattr(self._bm25, "idf"):
            min_idf = 0.1
            for word in self._bm25.idf:
                if self._bm25.idf[word] <= 0:
                    self._bm25.idf[word] = min_idf
        logger.info("bm25_index_rebuilt", document_count=len(self._doc_ids))

    def query(self, query_text: str, n_results: int = 10) -> list[tuple[str, float]]:
        if self._bm25 is None or not self._doc_ids:
            return []
        tokenized_query = _tokenize(query_text)
        if not tokenized_query:
            return []
        scores = self._bm25.get_scores(tokenized_query)
        indexed_scores = list(enumerate(scores))
        indexed_scores.sort(key=lambda x: x[1], reverse=True)
        results = []
        for idx, score in indexed_scores[:n_results]:
            if score > 0:
                results.append((self._doc_ids[idx], float(score)))
        return results

    @property
    def count(self) -> int:
        return len(self._doc_ids)

    def save(self, directory: str) -> None:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        data = {"doc_ids": self._doc_ids, "doc_texts": self._doc_texts}
        (path / "bm25_data.json").write_text(
            json.dumps(data, ensure_ascii=False), encoding="utf-8"
        )
        logger.info("bm25_index_saved", path=str(path), count=len(self._doc_ids))

    def load(self, directory: str) -> bool:
        path = Path(directory) / "bm25_data.json"
        if not path.exists():
            return False
        data = json.loads(path.read_text(encoding="utf-8"))
        self._doc_ids, self._doc_texts, self._seen = [], [], set()
        for doc_id, text in zip(data["doc_ids"], data["doc_texts"], strict=True):
            if doc_id in self._seen:
                continue
            self._seen.add(doc_id)
            self._doc_ids.append(doc_id)
            self._doc_texts.append(text)
        self._rebuild_index()
        logger.info("bm25_index_loaded", count=len(self._doc_ids))
        return True

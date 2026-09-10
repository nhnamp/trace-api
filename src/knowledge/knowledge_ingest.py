from __future__ import annotations

import json
from pathlib import Path

import structlog

from src.knowledge.rag_engine import CVEDocument, RAGEngine

logger = structlog.get_logger(__name__)


class KnowledgeIngestor:
    def __init__(self, rag_engine: RAGEngine) -> None:
        self.rag_engine = rag_engine

    def ingest_have_poc(
        self,
        path: str | Path,
        exclude_cves: set[str] | None = None,
    ) -> int:
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        cves = data.get("cves", [])
        if not cves:
            logger.warning("no_cves_in_have_poc", path=str(path))
            return 0

        exclude_cves = exclude_cves or set()
        skipped = 0

        documents = []
        for entry in cves:
            cve_id = entry.get("cve_id", "")
            if not cve_id:
                continue
            if cve_id in exclude_cves:
                skipped += 1
                continue

            chain_of_thought = entry.get("chain_of_thought")
            exploit_method = None
            if chain_of_thought:
                steps = [
                    f"{s.get('action', '')}: {s.get('details', '')}"
                    for s in chain_of_thought
                ]
                exploit_method = " -> ".join(steps)

            doc = CVEDocument(
                doc_id=f"havepoc-{cve_id}",
                cve_id=cve_id,
                title=entry.get("task_name", ""),
                description=entry.get("task_description", ""),
                vulnerability_type=entry.get("vulnerability_type", ""),
                affected_component=entry.get("target_method", ""),
                target_library=entry.get("target_library"),
                exploit_method=exploit_method,
                poc_script=entry.get("full_poc_script"),
                chain_of_thought=chain_of_thought,
                source="HavePoC.json",
            )
            documents.append(doc)

        added = self.rag_engine.add_documents(documents)
        logger.info(
            "have_poc_ingested",
            path=str(path),
            entries=len(cves),
            added=added,
            skipped=skipped,
        )
        return added

    def ingest_no_poc(
        self,
        path: str | Path,
        exclude_cves: set[str] | None = None,
    ) -> int:
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            logger.warning("unexpected_format_no_poc", path=str(path))
            return 0

        exclude_cves = exclude_cves or set()
        skipped = 0

        documents = []
        for entry in data:
            cve_id = entry.get("cve_id", "")
            if not cve_id:
                continue
            if cve_id in exclude_cves:
                skipped += 1
                continue
            doc = CVEDocument(
                doc_id=f"nopoc-{cve_id}",
                cve_id=cve_id,
                description=f"{cve_id}: {entry.get('vulnerability_type', 'Unknown vulnerability')}",
                vulnerability_type=entry.get("vulnerability_type", ""),
                source="NoPoC.json",
            )
            documents.append(doc)

        added = self.rag_engine.add_documents(documents)
        logger.info(
            "no_poc_ingested",
            path=str(path),
            entries=len(data),
            added=added,
            skipped=skipped,
        )
        return added

    def _collect_dataset_cve_ids(self, dataset_dir: Path) -> set[str]:
        cve_ids: set[str] = set()
        for entry in dataset_dir.iterdir():
            if entry.is_dir() and entry.name.startswith("CVE-"):
                cve_ids.add(entry.name)
        return cve_ids

    def ingest_dataset(self, dataset_dir: str | Path) -> int:
        dataset_dir = Path(dataset_dir)
        total = 0

        exclude_cves = self._collect_dataset_cve_ids(dataset_dir)

        have_poc = dataset_dir / "HavePoC.json"
        if have_poc.exists():
            total += self.ingest_have_poc(have_poc, exclude_cves)

        no_poc = dataset_dir / "NoPoC.json"
        if no_poc.exists():
            total += self.ingest_no_poc(no_poc, exclude_cves)

        logger.info(
            "dataset_ingestion_complete",
            total_added=total,
            excluded=len(exclude_cves),
        )
        return total

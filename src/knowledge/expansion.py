from __future__ import annotations

import json
import re
from pathlib import Path

import structlog

from src.knowledge.rag_engine import CVEDocument, RAGEngine

logger = structlog.get_logger(__name__)


class KnowledgeExpander:
    def __init__(self, rag_engine: RAGEngine) -> None:
        self.rag_engine = rag_engine

    def ingest_nvd_json(self, path: str | Path) -> int:
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))

        items = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("CVE_Items", data.get("vulnerabilities", []))
            if not items and "cve" in data:
                items = [data]

        if not items:
            logger.warning("nvd_no_items", path=str(path))
            return 0

        documents = []
        for item in items:
            doc = self._parse_nvd_item(item)
            if doc:
                documents.append(doc)

        added = self.rag_engine.add_documents(documents)
        logger.info("nvd_ingested", path=str(path), items=len(items), added=added)
        return added

    def _parse_nvd_item(self, item: dict) -> CVEDocument | None:
        cve_data = item.get("cve", item)
        cve_id = ""

        if "CVE_data_meta" in cve_data:
            cve_id = cve_data["CVE_data_meta"].get("ID", "")
        elif "id" in cve_data:
            cve_id = cve_data["id"]
        elif "cve_id" in cve_data:
            cve_id = cve_data["cve_id"]

        if not cve_id:
            return None

        description = ""
        desc_data = cve_data.get("description", {})
        if isinstance(desc_data, dict):
            for d in desc_data.get("description_data", []):
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            if not description:
                for d in desc_data.get("descriptions", []):
                    if d.get("lang") == "en":
                        description = d.get("value", "")
                        break
        elif isinstance(desc_data, str):
            description = desc_data

        if not description and "descriptions" in cve_data:
            for d in cve_data["descriptions"]:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break

        vuln_type = self._extract_vuln_type(item)
        affected = self._extract_affected_component(item)

        return CVEDocument(
            doc_id=f"nvd-{cve_id}",
            cve_id=cve_id,
            title=cve_id,
            description=description,
            vulnerability_type=vuln_type,
            affected_component=affected,
            source="NVD",
        )

    def _extract_vuln_type(self, item: dict) -> str:
        problemtype = item.get("cve", item).get("problemtype", {})
        for pt in problemtype.get("problemtype_data", []):
            for desc in pt.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    return val
        weaknesses = item.get("cve", item).get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    return val
        return ""

    def _extract_affected_component(self, item: dict) -> str:
        configs = item.get("configurations", {})
        nodes = configs.get("nodes", [])
        for node in nodes:
            for match in node.get("cpe_match", []):
                uri = match.get("cpe23Uri", match.get("criteria", ""))
                if uri:
                    parts = uri.split(":")
                    if len(parts) >= 5:
                        return f"{parts[3]}:{parts[4]}"
        return ""

    def ingest_markdown(self, path: str | Path) -> int:
        path = Path(path)
        content = path.read_text(encoding="utf-8")

        cve_id = self._extract_cve_from_filename(path.stem)
        if not cve_id:
            cve_id = self._extract_cve_from_content(content)
        if not cve_id:
            logger.warning("no_cve_id_in_markdown", path=str(path))
            return 0

        title = ""
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                title = stripped.lstrip("#").strip()
                break

        vuln_type = self._detect_vuln_type_from_text(content)

        doc = CVEDocument(
            doc_id=f"md-{cve_id}-{path.stem}",
            cve_id=cve_id,
            title=title or cve_id,
            description=content[:2000],
            vulnerability_type=vuln_type,
            source=f"markdown:{path.name}",
        )

        added = self.rag_engine.add_documents([doc])
        logger.info("markdown_ingested", path=str(path), cve_id=cve_id, added=added)
        return added

    def ingest_markdown_directory(self, directory: str | Path) -> int:
        directory = Path(directory)
        if not directory.is_dir():
            logger.warning("markdown_dir_not_found", path=str(directory))
            return 0

        total = 0
        for md_file in sorted(directory.glob("**/*.md")):
            total += self.ingest_markdown(md_file)

        logger.info("markdown_dir_ingested", directory=str(directory), total=total)
        return total

    def ingest_custom_json(self, path: str | Path) -> int:
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))

        if isinstance(data, dict):
            data = data.get("documents", data.get("cves", [data]))
        if not isinstance(data, list):
            logger.warning("custom_json_invalid_format", path=str(path))
            return 0

        documents = []
        for i, entry in enumerate(data):
            cve_id = entry.get("cve_id", "")
            if not cve_id:
                continue
            doc = CVEDocument(
                doc_id=f"custom-{cve_id}-{i}",
                cve_id=cve_id,
                title=entry.get("title", cve_id),
                description=entry.get("description", ""),
                vulnerability_type=entry.get("vulnerability_type", ""),
                affected_component=entry.get("affected_component", ""),
                target_library=entry.get("target_library"),
                exploit_method=entry.get("exploit_method"),
                poc_script=entry.get("poc_script"),
                preconditions=entry.get("preconditions", []),
                success_indicators=entry.get("success_indicators", []),
                source=f"custom:{path.name}",
            )
            documents.append(doc)

        added = self.rag_engine.add_documents(documents)
        logger.info("custom_json_ingested", path=str(path), entries=len(data), added=added)
        return added

    def _extract_cve_from_filename(self, stem: str) -> str:
        match = re.search(r"(CVE-\d{4}-\d{4,})", stem, re.IGNORECASE)
        return match.group(1).upper() if match else ""

    def _extract_cve_from_content(self, content: str) -> str:
        match = re.search(r"(CVE-\d{4}-\d{4,})", content, re.IGNORECASE)
        return match.group(1).upper() if match else ""

    def _detect_vuln_type_from_text(self, text: str) -> str:
        text_lower = text.lower()
        vuln_patterns = [
            ("SQL Injection", ["sql injection", "sqli", "sql inject"]),
            ("Cross-Site Scripting", ["cross-site scripting", "xss", "reflected xss", "stored xss"]),
            ("Path Traversal", ["path traversal", "directory traversal", "lfi", "local file inclusion"]),
            ("Remote Code Execution", ["remote code execution", "rce", "command injection"]),
            ("Server-Side Request Forgery", ["ssrf", "server-side request forgery"]),
            ("IDOR", ["idor", "insecure direct object reference", "bola"]),
            ("Authentication Bypass", ["authentication bypass", "auth bypass"]),
            ("Deserialization", ["deserialization", "insecure deserialization"]),
            ("XML External Entity", ["xxe", "xml external entity"]),
            ("Open Redirect", ["open redirect"]),
        ]
        for vuln_type, keywords in vuln_patterns:
            for kw in keywords:
                if kw in text_lower:
                    return vuln_type
        return ""

    def get_stats(self) -> dict:
        return {
            "total_documents": len(self.rag_engine._documents),
            "sources": self._count_by_source(),
        }

    def _count_by_source(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for doc in self.rag_engine._documents.values():
            base_source = doc.source.split(":")[0]
            counts[base_source] = counts.get(base_source, 0) + 1
        return counts

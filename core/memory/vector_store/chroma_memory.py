"""
VectorMemory: ChromaDB-backed semantic memory for attack learning.

Stores embeddings of successful attacks. On new engagements, retrieves
the most semantically similar past attacks to inform the planner.

The learning loop:
  Attack succeeds → embed (type + prompt + target_desc) → store in Chroma
  New target arrives → embed target_desc → query top-K similar past attacks
  Planner receives retrieved attacks → adapts strategy accordingly

This is the core continuous learning mechanism.
"""

from __future__ import annotations
import logging
import os
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

from core.executor.garak_runner.runner import Finding

logger = logging.getLogger(__name__)

DEFAULT_EMBEDDING_MODEL = "all-MiniLM-L6-v2"
DEFAULT_COLLECTION = "attack_memory"
DEFAULT_PERSIST_DIR = "./data/chroma_db"


def _load_config() -> dict[str, Any]:
    """Load settings from config/settings.yaml."""
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "settings.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


@dataclass
class MemoryEntry:
    """A stored attack memory entry in ChromaDB."""
    memory_id: str
    text: str
    attack_type: str
    category: str
    severity: str
    severity_score: float
    timestamp: str
    metadata: dict[str, Any]
    distance: float = 1.0


class ChromaMemory:
    """
    Manages semantic attack memory using ChromaDB.

    Embeddings are generated with sentence-transformers (CPU-only).
    Falls back to TF-IDF if sentence-transformers fails due to memory.
    """

    def __init__(
        self,
        persist_dir: Optional[str] = None,
        collection_name: str = DEFAULT_COLLECTION,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    ) -> None:
        """
        Args:
            persist_dir: Path for ChromaDB persistence (from .env).
            collection_name: ChromaDB collection name.
            embedding_model: sentence-transformers model name.
        """
        self._disabled = os.getenv("DISABLE_VECTOR_MEMORY", "false").lower() == "true"
        if self._disabled:
            logger.info("Vector memory disabled via DISABLE_VECTOR_MEMORY=true")
            self._chromadb = None
            self._collection = None
            self._model = None
            self._model_name = embedding_model
            self._model_available = False
            self._memory_entries = []
            return

        config = _load_config()
        memory_config = config.get("memory", {})

        self.persist_dir = persist_dir or memory_config.get("chroma_path", DEFAULT_PERSIST_DIR)
        self.collection_name = collection_name
        self._model_name = os.getenv("EMBEDDING_MODEL", embedding_model)

        self._model = None
        self._model_available = None
        self._tfidf_vectorizer = None
        self._tfidf_matrix = None
        self._chromadb = None
        self._collection = None
        self._use_tfidf = False
        self._memory_entries = []

        self._init_chromadb()

    def _init_chromadb(self) -> None:
        """Initialize ChromaDB with lazy model loading."""
        try:
            import chromadb
            from chromadb.config import Settings

            Path(self.persist_dir).mkdir(parents=True, exist_ok=True)

            self._chromadb = chromadb.PersistentClient(
                path=self.persist_dir,
                settings=Settings(anonymized_telemetry=False),
            )

            try:
                self._collection = self._chromadb.get_collection(
                    name=self.collection_name
                )
            except Exception:
                self._collection = self._chromadb.create_collection(
                    name=self.collection_name,
                    metadata={"hnsw:space": "cosine"},
                )

        except Exception as e:
            logger.warning(f"Failed to initialize ChromaDB: {e}")
            self._disabled = True

    def _get_model(self):
        """Lazy load the embedding model with timeout."""
        if self._disabled:
            return None
        if self._model is not None:
            return self._model
        if self._model_available is False:
            return None

        try:
            from sentence_transformers import SentenceTransformer

            cache_folder = os.getenv(
                "SENTENCE_TRANSFORMERS_HOME",
                str(Path.home() / ".cache" / "sentence_transformers")
            )

            if sys.platform == "win32":
                result = [None]
                error = [None]

                def _load():
                    try:
                        result[0] = SentenceTransformer(
                            self._model_name,
                            cache_folder=cache_folder
                        )
                    except Exception as e:
                        error[0] = e

                t = threading.Thread(target=_load, daemon=True)
                t.start()
                t.join(timeout=30)

                if t.is_alive():
                    logger.warning(f"Model load exceeded 30s, using fallback")
                    self._model_available = False
                    return None
                if error[0]:
                    raise error[0]
                self._model = result[0]
            else:
                import signal

                def _timeout_handler(signum, frame):
                    raise TimeoutError("Model load timed out")

                signal.signal(signal.SIGALRM, _timeout_handler)
                signal.alarm(30)
                try:
                    self._model = SentenceTransformer(
                        self._model_name,
                        cache_folder=cache_folder
                    )
                finally:
                    signal.alarm(0)

            self._model_available = True
            logger.info(f"Loaded embedding model: {self._model_name}")
            return self._model

        except ImportError:
            self._model_available = False
            logger.warning(
                "sentence-transformers not installed. "
                "Vector memory disabled. Run: pip install sentence-transformers"
            )
            return None
        except Exception as e:
            self._model_available = False
            logger.warning(
                f"Embedding model failed to load: {e}. "
                "Vector memory running without embeddings. "
                "Pre-download with: python -c \"from sentence_transformers "
                "import SentenceTransformer; "
                "SentenceTransformer('all-MiniLM-L6-v2')\""
            )
            return None

    def _load_embedding_model(self) -> None:
        """Load sentence-transformers model with memory guard."""
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.embedding_model_name)
            logger.info(f"Loaded embedding model: {self.embedding_model_name}")
        except Exception as e:
            logger.warning(f"Failed to load sentence-transformers: {e}")
            self._try_tfidf_fallback()

    def _try_tfidf_fallback(self) -> None:
        """Try TF-IDF fallback when sentence-transformers fails."""
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            self._tfidf_vectorizer = TfidfVectorizer(max_features=384)
            self._use_tfidf = True
            logger.info("Falling back to TF-IDF vectorization")
        except ImportError:
            logger.warning(
                "Vector memory disabled — insufficient RAM. "
                "Install: pip install sentence-transformers"
            )
            self._disabled = True

    def store_successful_attack(
        self,
        finding: Finding,
        target_description: str,
        engagement_id: str = "",
    ) -> str:
        """
        Embed and store a successful attack finding in ChromaDB.

        Args:
            finding: Finding object with full context.
            target_description: Plain-English description of the target system.
            engagement_id: Optional engagement ID for deletion.

        Returns:
            memory_id of the stored entry.
        """
        if self._disabled:
            logger.warning("Vector memory disabled, skipping store")
            return ""

        memory_id = str(uuid.uuid4())
        text = self._build_document_text(finding, target_description)

        try:
            if self._use_tfidf and self._tfidf_vectorizer:
                if self._tfidf_matrix is None:
                    self._tfidf_vectorizer.fit([text])
                    embedding = self._tfidf_vectorizer.transform([text]).toarray()[0].tolist()
                else:
                    embedding = self._tfidf_vectorizer.transform([text]).toarray()[0].tolist()

                self._memory_entries.append({
                    "id": memory_id,
                    "text": text,
                    "embedding": embedding,
                    "metadata": self._build_metadata(finding, engagement_id),
                })
            else:
                model = self._get_model()
                if model is not None:
                    embedding = model.encode(text).tolist()
                    self._collection.add(
                        documents=[text],
                        embeddings=[embedding],
                        metadatas=[self._build_metadata(finding, engagement_id)],
                        ids=[memory_id],
                    )
                else:
                    self._collection.add(
                        documents=[text],
                        metadatas=[self._build_metadata(finding, engagement_id)],
                        ids=[memory_id],
                    )

            logger.info(f"Stored attack in vector memory: {memory_id}")
            return memory_id

        except Exception as e:
            logger.error(f"Failed to store attack: {e}")
            return ""

    def _build_metadata(self, finding: Finding, engagement_id: str) -> dict[str, Any]:
        """Build metadata dict from finding fields."""
        return {
            "attack_type": finding.attack_type,
            "category": finding.category,
            "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            "severity_score": finding.severity_score,
            "target_url": finding.target_url,
            "probe_name": finding.probe_name,
            "engagement_id": engagement_id,
            "created_at": finding.timestamp or "",
        }

    def _build_document_text(self, finding: Finding, target_description: str) -> str:
        """Construct the text string that will be embedded."""
        category = finding.category or "unknown"
        attack_type = finding.attack_type or "unknown"
        prompt_snippet = (finding.attack_prompt or "")[:200]

        return f"{category}: {attack_type} attack on {target_description}. Prompt: {prompt_snippet}"

    def retrieve_similar_attacks(
        self,
        target_description: str,
        attack_type: str = "",
        top_k: int = 5,
    ) -> list[MemoryEntry]:
        """
        Find the most semantically similar past successful attacks.

        Args:
            target_description: Description of the new target system.
            attack_type: Optional filter by attack type.
            top_k: Number of results to return.

        Returns:
            List of MemoryEntry objects ordered by similarity (most similar first).
        """
        if self._disabled:
            return []

        query = f"{attack_type} attack on {target_description}" if attack_type else target_description

        try:
            if self._use_tfidf and self._tfidf_vectorizer:
                return self._tfidf_retrieve(query, top_k)

            embedding = self._model.encode(query).tolist()

            where_filter = {"attack_type": attack_type} if attack_type else None

            results = self._collection.query(
                query_embeddings=[embedding],
                n_results=top_k,
                where=where_filter,
            )

            entries = []
            if results and results.get("ids") and results["ids"][0]:
                for i, mem_id in enumerate(results["ids"][0]):
                    distance = results["distances"][0][i] if results.get("distances") else 1.0

                    if distance > 0.8:
                        continue

                    metadata = results["metadatas"][0][i] if results.get("metadatas") else {}
                    document = results["documents"][0][i] if results.get("documents") else ""

                    entries.append(MemoryEntry(
                        memory_id=mem_id,
                        text=document,
                        attack_type=metadata.get("attack_type", "unknown"),
                        category=metadata.get("category", "unknown"),
                        severity=metadata.get("severity", "info"),
                        severity_score=metadata.get("severity_score", 0.0),
                        timestamp=metadata.get("created_at", ""),
                        metadata=metadata,
                        distance=distance,
                    ))

            return entries

        except Exception as e:
            logger.error(f"Failed to retrieve similar attacks: {e}")
            return []

    def _tfidf_retrieve(self, query: str, top_k: int) -> list[MemoryEntry]:
        """TF-IDF based retrieval when sentence-transformers is unavailable."""
        if not self._memory_entries:
            return []

        query_embedding = self._tfidf_vectorizer.transform([query]).toarray()[0].tolist()

        from sklearn.metrics.pairwise import cosine_similarity
        similarities = []
        for entry in self._memory_entries:
            sim = cosine_similarity([query_embedding], [entry["embedding"]])[0][0]
            if sim >= 0.2:
                similarities.append((1 - sim, entry))

        similarities.sort(key=lambda x: x[0])

        entries = []
        for distance, entry in similarities[:top_k]:
            if distance > 0.8:
                continue
            metadata = entry["metadata"]
            entries.append(MemoryEntry(
                memory_id=entry["id"],
                text=entry["text"],
                attack_type=metadata.get("attack_type", "unknown"),
                category=metadata.get("category", "unknown"),
                severity=metadata.get("severity", "info"),
                severity_score=metadata.get("severity_score", 0.0),
                timestamp=metadata.get("created_at", ""),
                metadata=metadata,
                distance=distance,
            ))

        return entries

    def get_attack_context(self, attack_type: str, target_description: str) -> str:
        """
        Get memory context for the Planner.

        Args:
            attack_type: Type of attack to search for.
            target_description: Description of the target.

        Returns:
            Formatted string of past successful attacks, or empty string.
        """
        if self._disabled:
            return ""

        results = self.retrieve_similar_attacks(
            target_description=target_description,
            attack_type=attack_type,
            top_k=3,
        )

        if not results:
            return ""

        lines = ["Past successful attacks:"]
        for entry in results:
            lines.append(f"- {entry.text[:100]}... (severity: {entry.severity})")

        return "\n".join(lines)

    def delete_engagement_attacks(self, engagement_id: str) -> int:
        """
        Delete all entries for a specific engagement.

        Args:
            engagement_id: The engagement ID to delete entries for.

        Returns:
            Number of entries deleted.
        """
        if self._disabled:
            return 0

        try:
            if self._use_tfidf:
                original_count = len(self._memory_entries)
                self._memory_entries = [
                    e for e in self._memory_entries
                    if e["metadata"].get("engagement_id") != engagement_id
                ]
                return original_count - len(self._memory_entries)

            results = self._collection.get(where={"engagement_id": engagement_id})
            if results and results.get("ids"):
                self._collection.delete(ids=results["ids"])
                return len(results["ids"])

            return 0

        except Exception as e:
            logger.error(f"Failed to delete engagement attacks: {e}")
            return 0

    def get_stats(self) -> dict[str, Any]:
        """
        Return collection stats: total entries, by_attack_type, by_severity.

        Returns:
            Dict with stats.
        """
        stats = {
            "total_entries": 0,
            "by_attack_type": {},
            "by_severity": {},
        }

        if self._disabled:
            return stats

        try:
            if self._use_tfidf:
                stats["total_entries"] = len(self._memory_entries)
                for entry in self._memory_entries:
                    at = entry["metadata"].get("attack_type", "unknown")
                    stats["by_attack_type"][at] = stats["by_attack_type"].get(at, 0) + 1

                    sev = entry["metadata"].get("severity", "info")
                    stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
                return stats

            all_data = self._collection.get()

            if all_data and all_data.get("metadatas"):
                stats["total_entries"] = len(all_data["metadatas"])

                for metadata in all_data["metadatas"]:
                    at = metadata.get("attack_type", "unknown")
                    stats["by_attack_type"][at] = stats["by_attack_type"].get(at, 0) + 1

                    sev = metadata.get("severity", "info")
                    stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1

            return stats

        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return stats

    def get_collection_stats(self) -> dict[str, Any]:
        """Return stats: total entries, entries by category, entries by severity."""
        return self.get_stats()


VectorMemory = ChromaMemory
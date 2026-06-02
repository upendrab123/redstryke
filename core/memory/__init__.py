"""
Memory package — dual-store architecture.
vector_store: ChromaDB for semantic similarity retrieval.
sql_store: SQLite for structured audit trail and analytics.
"""
__all__ = ["VectorMemory", "SQLMemory", "MemoryManager"]
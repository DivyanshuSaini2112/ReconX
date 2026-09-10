"""Long-term memory: persists findings, playbooks, and target profiles across scans.
Uses ChromaDB for semantic similarity search + SQLite for structured queries.

Key benefit: after solving 10 HTB machines with PHP deserialization -> RCE,
the agent recognizes that pattern early on similar targets.
"""

CHROMADB_PATH = "./nexus_memory"


class PlaybookRetriever:
    """Retrieve past successful exploit chains for similar tech stacks."""

    def __init__(self):
        try:
            import chromadb
            self.client = chromadb.PersistentClient(path=CHROMADB_PATH)
            self.collection = self.client.get_or_create_collection("playbooks")
        except ImportError:
            self.client = None
            self.collection = None

    def retrieve(self, tech_stack: list, top_k: int = 3) -> list:
        """Find past exploit chains that worked on a similar tech stack."""
        if self.collection is None:
            return []
        query = " ".join(tech_stack)
        results = self.collection.query(query_texts=[query], n_results=top_k)
        return results.get("documents", [[]])[0]

    def store(self, tech_stack: list, exploit_chain: dict) -> None:
        """Persist a successful exploit chain for future retrieval."""
        if self.collection is None:
            return
        import json
        self.collection.add(
            documents=[json.dumps(exploit_chain)],
            metadatas=[{"tech_stack": ",".join(tech_stack)}],
            ids=[exploit_chain.get("id", str(id(exploit_chain)))],
        )

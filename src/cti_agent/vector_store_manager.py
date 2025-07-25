
import chromadb
from chromadb.utils import embedding_functions

class VectorStoreManager:
    def __init__(self, host="localhost", port=8000):
        self.client = chromadb.HttpClient(host=host, port=port)
        self.embedding_function = embedding_functions.DefaultEmbeddingFunction()
        self.collection = self.client.get_or_create_collection(
            name="cve_details",
            embedding_function=self.embedding_function
        )

    def add_document(self, document, metadata, doc_id):
        self.collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[doc_id]
        )

    def search(self, query, n_results=2, where=None):
        return self.collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where
        )

    def document_exists(self, doc_id):
        """Checks if a document with the given ID already exists in the collection."""
        results = self.collection.get(ids=[doc_id])
        return len(results.get('ids', [])) > 0

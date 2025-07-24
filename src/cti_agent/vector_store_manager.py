
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

    def search(self, query, n_results=2):
        return self.collection.query(
            query_texts=[query],
            n_results=n_results
        )

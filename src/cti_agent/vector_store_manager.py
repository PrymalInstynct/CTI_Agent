import chromadb
from chromadb.utils import embedding_functions
from typing import List, Dict, Any
import uuid
import numpy as np

def chunk_text(text: str, chunk_size: int = 500, chunk_overlap: int = 50) -> List[str]:
    """
    Splits a given text into smaller chunks.
    """
    chunks = []
    if not text:
        return chunks
    for i in range(0, len(text), chunk_size - chunk_overlap):
        chunks.append(text[i:i + chunk_size])
    return chunks

class VectorStoreManager:
    def __init__(self, host="localhost", port=8000):
        self.client = chromadb.HttpClient(host=host, port=port)
        self.embedding_function = embedding_functions.DefaultEmbeddingFunction()
        self.collection = self.client.get_or_create_collection(
            name="cve_details",
            embedding_function=self.embedding_function
        )

    def add_document(self, document: str, metadata: Dict[str, Any], doc_id: str):
        if self.document_exists(doc_id):
            print(f"Document with ID {doc_id} already exists. Skipping.")
            return

        chunks = chunk_text(document)
        
        documents_to_add = []
        metadatas_to_add = []
        ids_to_add = []

        for i, chunk in enumerate(chunks):
            chunk_id = f"{doc_id}-{i}"
            chunk_metadata = {**metadata, "chunk_index": i, "total_chunks": len(chunks)}
            documents_to_add.append(chunk)
            metadatas_to_add.append(chunk_metadata)
            ids_to_add.append(chunk_id)
        
        if documents_to_add:
            self.collection.add(
                documents=documents_to_add,
                metadatas=metadatas_to_add,
                ids=ids_to_add
            )
            print(f"Added {len(documents_to_add)} chunks for document ID {doc_id}.")
        else:
            print(f"No chunks generated for document ID {doc_id}. Not adding.")

    def search(self, query: str, k: int = 5, where: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Searches the vector store for the most relevant documents.
        """
        results = self.collection.query(
            query_texts=[query],
            n_results=k,
            where=where,
            include=['documents', 'metadatas', 'distances']
        )
        
        if not results or not results.get('ids') or not results['ids'][0]:
            return []

        # Reconstruct the results into a list of dictionaries
        output = []
        num_results = len(results['ids'][0])
        for i in range(num_results):
            output.append({
                'id': results['ids'][0][i],
                'document': results['documents'][0][i] if results['documents'] else None,
                'metadata': results['metadatas'][0][i] if results['metadatas'] else None,
                'distance': results['distances'][0][i] if results['distances'] else None,
            })
        return output

    def document_exists(self, doc_id: str) -> bool:
        """
        Checks if a document with the given base ID already exists.
        """
        # Check for the first chunk of the document.
        results = self.collection.get(ids=[f"{doc_id}-0"])
        return len(results.get('ids', [])) > 0
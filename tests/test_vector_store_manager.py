import pytest
from src.cti_agent.vector_store_manager import VectorStoreManager, chunk_text
import chromadb
from unittest.mock import MagicMock, patch

# Mock the chromadb.HttpClient for isolated testing
@pytest.fixture
def mock_chroma_client():
    with patch('chromadb.HttpClient') as MockClient:
        mock_collection = MagicMock()
        mock_client_instance = MagicMock()
        mock_client_instance.get_or_create_collection.return_value = mock_collection
        MockClient.return_value = mock_client_instance
        yield mock_client_instance, mock_collection

@pytest.fixture
def vector_store_manager(mock_chroma_client):
    mock_client_instance, mock_collection = mock_chroma_client
    manager = VectorStoreManager()
    manager.collection = mock_collection # Ensure the mock collection is used
    return manager

def test_chunk_text_basic():
    text = "This is a short sentence. This is another one. And a third."
    chunks = chunk_text(text, chunk_size=30, chunk_overlap=0)
    assert len(chunks) == 3
    assert chunks[0] == "This is a short sentence."
    assert chunks[1] == "This is another one."
    assert chunks[2] == "And a third."

def test_chunk_text_with_overlap():
    text = "This is a long sentence that needs to be chunked with overlap."
    chunks = chunk_text(text, chunk_size=20, chunk_overlap=5)
    assert len(chunks) > 1
    assert chunks[0] == "This is a long sen"
    assert chunks[1] == "sentence that need" # Example, actual overlap might vary slightly based on implementation
    # More robust checks would involve verifying overlap content

def test_chunk_text_empty():
    chunks = chunk_text("", chunk_size=100)
    assert chunks == []

def test_chunk_text_single_large_paragraph():
    text = "a" * 1000
    chunks = chunk_text(text, chunk_size=100, chunk_overlap=0)
    assert len(chunks) == 10
    assert all(len(c) == 100 for c in chunks)

def test_add_document_new(vector_store_manager):
    doc_id = "test_doc_1"
    document = "This is a test document content."
    metadata = {"source": "test", "cve_id": "CVE-2023-0001"}
    
    vector_store_manager.collection.get.return_value = {'ids': []} # Document does not exist
    
    vector_store_manager.add_document(document, metadata, doc_id)
    
    vector_store_manager.collection.add.assert_called_once()
    args, kwargs = vector_store_manager.collection.add.call_args
    assert len(kwargs['documents']) == 1
    assert kwargs['documents'][0] == document
    assert kwargs['metadatas'][0]['source'] == "test"
    assert kwargs['metadatas'][0]['chunk_index'] == 0
    assert kwargs['ids'][0] == f"{doc_id}-0"

def test_add_document_existing(vector_store_manager):
    doc_id = "test_doc_2"
    document = "This is a test document content."
    metadata = {"source": "test", "cve_id": "CVE-2023-0002"}
    
    vector_store_manager.collection.get.return_value = {'ids': [f"{doc_id}-0"]} # Document exists
    
    vector_store_manager.add_document(document, metadata, doc_id)
    
    vector_store_manager.collection.add.assert_not_called() # Should not add if exists

def test_document_exists(vector_store_manager):
    doc_id = "existing_doc"
    vector_store_manager.collection.get.return_value = {'ids': [f"{doc_id}-0"]}
    assert vector_store_manager.document_exists(doc_id)

    doc_id = "non_existing_doc"
    vector_store_manager.collection.get.return_value = {'ids': []}
    assert not vector_store_manager.document_exists(doc_id)

def test_search_mmr(vector_store_manager):
    query = "test query"
    k = 2
    fetch_k = 5
    
    # Mock initial query results with embeddings
    mock_initial_results = {
        'documents': [['doc1', 'doc2', 'doc3', 'doc4', 'doc5']],
        'metadatas': [[{}, {}, {}, {}, {}]],
        'ids': [['id1', 'id2', 'id3', 'id4', 'id5']],
        'distances': [[0.1, 0.2, 0.3, 0.4, 0.5]], # Lower distance is more relevant
        'embeddings': [[
            [0.1, 0.1], [0.2, 0.2], [0.9, 0.9], [0.15, 0.15], [0.8, 0.8]
        ]]
    }
    vector_store_manager.collection.query.return_value = mock_initial_results
    
    # Mock embedding function for query
    vector_store_manager.embedding_function.return_value = [[0.1, 0.1]] # Query embedding
    
    results = vector_store_manager.search(query, k=k, fetch_k=fetch_k)
    
    assert len(results['documents']) == k
    # Further assertions could check the MMR logic, but that's more complex to mock precisely.
    # This test primarily ensures the method is called correctly and returns expected structure.

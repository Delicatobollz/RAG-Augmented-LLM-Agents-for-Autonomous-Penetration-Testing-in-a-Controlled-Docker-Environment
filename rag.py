import chromadb
from chromadb.utils import embedding_functions
import uuid
from datetime import datetime

# Try both hostnames
client = None
scan_collection = None

try:
    client = chromadb.HttpClient(host="chromadb", port=8000)
    client.heartbeat()
    print("[*] ChromaDB connected via 'chromadb'")
except:
    try:
        client = chromadb.HttpClient(host="172.18.0.5", port=8000)
        client.heartbeat()
        print("[*] ChromaDB connected via IP")
    except Exception as e:
        print(f"[!] ChromaDB connection failed: {e}")

if client:
    try:
        embedding_fn = embedding_functions.OllamaEmbeddingFunction(
            url="http://ollama:11434",
            model_name="nomic-embed-text"
        )
        scan_collection = client.get_or_create_collection(
            name="scan_results",
            embedding_function=embedding_fn
        )
        print("[*] ChromaDB collection ready")
    except Exception as e:
        print(f"[!] ChromaDB collection error: {e}")

def store_result(content: str, metadata: dict = None) -> str:
    """Store a scan result in ChromaDB."""
    if not scan_collection:
        print("[!] ChromaDB not available, skipping storage")
        return "no-storage"
    try:
        doc_id = str(uuid.uuid4())
        meta = {
            "timestamp": datetime.now().isoformat(),
            "type": "scan"
        }
        if metadata:
            meta.update(metadata)
        scan_collection.add(
            documents=[content],
            metadatas=[meta],
            ids=[doc_id]
        )
        return doc_id
    except Exception as e:
        print(f"[!] Storage error: {e}")
        return "error"

def search_results(query: str, n_results: int = 3) -> dict:
    """Search stored scan results by semantic similarity."""
    if not scan_collection:
        return {"documents": [[]], "metadatas": [[]]}
    try:
        return scan_collection.query(
            query_texts=[query],
            n_results=n_results
        )
    except Exception as e:
        print(f"[!] Search error: {e}")
        return {"documents": [[]], "metadatas": [[]]}

def already_ingested(filename: str) -> bool:
    """Check if a file has already been ingested."""
    if not scan_collection:
        return False
    try:
        results = scan_collection.get(
            where={"source": filename}
        )
        return len(results['ids']) > 0
    except:
        return False

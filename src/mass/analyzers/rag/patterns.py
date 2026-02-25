"""Risk patterns for RAG pipeline components.

Detects security issues in vector database usage, embedding pipelines,
document ingestion, and retrieval code.
"""

from dataclasses import dataclass, field
from enum import Enum

from mass.core.types import Severity


class RAGRiskCategory(str, Enum):
    """Categories of RAG pipeline risk."""

    UNVALIDATED_INGESTION = "unvalidated_ingestion"
    UNAUTHENTICATED_VECTORDB = "unauthenticated_vectordb"
    NO_ACCESS_CONTROL = "no_access_control"
    UNSIGNED_EMBEDDING_MODEL = "unsigned_embedding_model"
    NO_RELEVANCE_FILTERING = "no_relevance_filtering"
    UNSANITIZED_RETRIEVAL = "unsanitized_retrieval"
    HARDCODED_CONNECTION = "hardcoded_connection"
    INSECURE_CHUNKING = "insecure_chunking"


@dataclass
class RAGPattern:
    """A single RAG risk pattern to search for."""

    id: str
    category: RAGRiskCategory
    title: str
    description: str
    severity: Severity
    code_patterns: list[str]  # regex patterns to match in source
    file_patterns: list[str] = field(default_factory=list)  # filename patterns
    remediation: str = ""


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

RAG_PATTERNS: list[RAGPattern] = [
    # Unvalidated document ingestion
    RAGPattern(
        id="RAG-001",
        category=RAGRiskCategory.UNVALIDATED_INGESTION,
        title="Document loader without input validation",
        description=(
            "Documents are loaded into the RAG pipeline without validation or "
            "sanitization. An attacker could inject malicious content into the "
            "knowledge base to influence model responses."
        ),
        severity=Severity.HIGH,
        code_patterns=[
            r"DirectoryLoader\s*\(",
            r"TextLoader\s*\(",
            r"PyPDFLoader\s*\(",
            r"UnstructuredFileLoader\s*\(",
            r"CSVLoader\s*\(",
            r"WebBaseLoader\s*\(",
            r"RecursiveUrlLoader\s*\(",
        ],
        file_patterns=["*loader*", "*ingest*", "*pipeline*", "*rag*"],
        remediation=(
            "Validate and sanitize all documents before ingestion. "
            "Implement content type checking, size limits, and malicious "
            "content scanning before adding to the knowledge base."
        ),
    ),
    # Unauthenticated vector DB access
    RAGPattern(
        id="RAG-002",
        category=RAGRiskCategory.UNAUTHENTICATED_VECTORDB,
        title="Vector database without authentication",
        description=(
            "Vector database connection does not use authentication. "
            "Unauthenticated access allows attackers to read, modify, or delete "
            "embedding data."
        ),
        severity=Severity.HIGH,
        code_patterns=[
            r"Chroma\(\s*\)",
            r"chromadb\.Client\(\s*\)",
            r"chromadb\.HttpClient\([^)]*(?!api_key|token|auth)",
            r"Qdrant[Cc]lient\(\s*['\"](?:localhost|127\.0\.0\.1)",
            r"Pinecone\(\s*\)",
            r"weaviate\.Client\(\s*url\s*=",
        ],
        file_patterns=["*vectordb*", "*vector*", "*chroma*", "*pinecone*", "*qdrant*", "*weaviate*", "*milvus*"],
        remediation=(
            "Enable authentication on all vector database connections. "
            "Use API keys, tokens, or certificate-based auth. "
            "Never expose vector DBs without access controls."
        ),
    ),
    # No chunk-level access control
    RAGPattern(
        id="RAG-003",
        category=RAGRiskCategory.NO_ACCESS_CONTROL,
        title="No chunk-level access control in retrieval",
        description=(
            "Retrieved chunks are not filtered by user permissions. "
            "All users can access all data in the knowledge base regardless "
            "of authorization level."
        ),
        severity=Severity.MEDIUM,
        code_patterns=[
            r"\.similarity_search\(",
            r"\.max_marginal_relevance_search\(",
            r"as_retriever\(\s*\)",
            r"VectorStoreRetriever\(",
        ],
        file_patterns=["*retriev*", "*search*", "*query*", "*rag*"],
        remediation=(
            "Implement metadata-based filtering on retrieved chunks. "
            "Tag documents with access levels during ingestion and filter "
            "results based on the requesting user's permissions."
        ),
    ),
    # Hardcoded connection strings
    RAGPattern(
        id="RAG-004",
        category=RAGRiskCategory.HARDCODED_CONNECTION,
        title="Hardcoded vector DB connection string",
        description=(
            "Vector database connection string or API key is hardcoded in source. "
            "Credentials may be exposed through version control."
        ),
        severity=Severity.HIGH,
        code_patterns=[
            r"""(?:api_key|token|password)\s*=\s*['"][^'"]{8,}['"]""",
            r"""(?:PINECONE_API_KEY|QDRANT_API_KEY|WEAVIATE_API_KEY)\s*=\s*['"][^'"]+['"]""",
            r"""connection_string\s*=\s*['"](?:postgresql|mongodb|redis)://[^'"]+['"]""",
        ],
        file_patterns=["*vector*", "*rag*", "*embed*", "*db*", "*config*"],
        remediation=(
            "Move all connection strings and API keys to environment variables "
            "or a secrets manager. Never commit credentials to source control."
        ),
    ),
    # No relevance filtering
    RAGPattern(
        id="RAG-005",
        category=RAGRiskCategory.NO_RELEVANCE_FILTERING,
        title="Retrieval without relevance score filtering",
        description=(
            "Retrieved chunks are passed to the LLM without filtering by "
            "relevance score. Low-relevance chunks may cause hallucination "
            "or be exploited for context poisoning."
        ),
        severity=Severity.MEDIUM,
        code_patterns=[
            r"similarity_search\([^)]*\)\s*(?!\[)",
            r"\.invoke\(\s*['\"]",
            r"RetrievalQA\.from_chain_type\(",
        ],
        file_patterns=["*rag*", "*retriev*", "*chain*", "*qa*"],
        remediation=(
            "Filter retrieved chunks by relevance score threshold. "
            "Implement similarity_search_with_score() and discard chunks "
            "below a configurable threshold (e.g., 0.7)."
        ),
    ),
    # Unsanitized retrieval output
    RAGPattern(
        id="RAG-006",
        category=RAGRiskCategory.UNSANITIZED_RETRIEVAL,
        title="Retrieved content not sanitized before LLM prompt",
        description=(
            "Content retrieved from the vector store is passed directly into "
            "the LLM prompt without sanitization. Poisoned documents could "
            "inject instructions into the prompt context."
        ),
        severity=Severity.HIGH,
        code_patterns=[
            r"context\s*=\s*['\"]\\n['\"]\.join",
            r"f['\"].*\{.*docs.*\}.*['\"]",
            r"\.format\(.*context.*\)",
            r"prompt_template.*\{context\}",
        ],
        file_patterns=["*rag*", "*chain*", "*prompt*", "*template*"],
        remediation=(
            "Sanitize retrieved content before including in prompts. "
            "Strip potential instruction patterns, limit chunk sizes, and "
            "use prompt delimiters to separate context from instructions."
        ),
    ),
    # Embedding model integrity
    RAGPattern(
        id="RAG-007",
        category=RAGRiskCategory.UNSIGNED_EMBEDDING_MODEL,
        title="Embedding model loaded without integrity verification",
        description=(
            "Embedding model is loaded from a remote source without hash "
            "verification or signature checking. A tampered model could "
            "produce adversarial embeddings."
        ),
        severity=Severity.MEDIUM,
        code_patterns=[
            r"HuggingFaceEmbeddings\(",
            r"SentenceTransformer\(",
            r"OpenAIEmbeddings\(",
            r"from_pretrained\(",
            r"OllamaEmbeddings\(",
        ],
        file_patterns=["*embed*", "*model*", "*rag*"],
        remediation=(
            "Pin embedding model versions and verify checksums. "
            "Use model registries with provenance tracking. "
            "Consider self-hosting embedding models for sensitive workloads."
        ),
    ),
    # Insecure chunking
    RAGPattern(
        id="RAG-008",
        category=RAGRiskCategory.INSECURE_CHUNKING,
        title="Document chunking without size limits",
        description=(
            "Text splitter does not enforce maximum chunk sizes, allowing "
            "oversized documents to consume excessive embedding resources "
            "or cause out-of-memory conditions."
        ),
        severity=Severity.LOW,
        code_patterns=[
            r"RecursiveCharacterTextSplitter\(",
            r"CharacterTextSplitter\(",
            r"TokenTextSplitter\(",
            r"text_splitter.*chunk_size\s*=\s*\d{5,}",
        ],
        file_patterns=["*chunk*", "*split*", "*ingest*", "*rag*"],
        remediation=(
            "Set reasonable chunk_size and chunk_overlap limits. "
            "Enforce maximum document size before chunking. "
            "Monitor embedding throughput for anomalies."
        ),
    ),
]


# File patterns that indicate RAG pipeline presence
RAG_INDICATOR_PATTERNS: list[str] = [
    "*rag*", "*retriev*", "*vector*", "*embed*",
    "*chroma*", "*pinecone*", "*qdrant*", "*weaviate*", "*milvus*",
    "*langchain*", "*llamaindex*", "*llama_index*",
    "*knowledge*", "*ingest*", "*loader*",
]

# Import patterns in code that suggest RAG usage
RAG_IMPORT_PATTERNS: list[str] = [
    r"from\s+langchain.*import.*(?:VectorStore|Chroma|FAISS|Pinecone|Qdrant)",
    r"from\s+llama_index.*import",
    r"import\s+chromadb",
    r"from\s+qdrant_client\s+import",
    r"import\s+pinecone",
    r"from\s+weaviate\s+import",
    r"from\s+pymilvus\s+import",
    r"from\s+sentence_transformers\s+import",
]

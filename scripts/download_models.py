#!/usr/bin/env python3
"""
Pre-downloads required ML models so ChromaMemory
does not hang on first run.
Run once before starting the platform:
  python scripts/download_models.py
"""
import sys


def download_embedding_model():
    model_name = "all-MiniLM-L6-v2"
    print(f"Downloading embedding model: {model_name}")
    print("This runs once and caches locally (~80MB)...")
    try:
        from sentence_transformers import SentenceTransformer
        m = SentenceTransformer(model_name)
        test = m.encode("test sentence")
        print(f"OK: model loaded, embedding dim: {len(test)}")
        return True
    except ImportError:
        print("SKIP: sentence-transformers not installed")
        print("Run: pip install sentence-transformers")
        return False
    except Exception as e:
        print(f"FAIL: {e}")
        return False


if __name__ == "__main__":
    ok = download_embedding_model()
    sys.exit(0 if ok else 1)
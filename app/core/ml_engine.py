
"""
Local ML Engine
Single entry point for all local model inference (CPU optimized).
Wraps HuggingFace transformers with efficient loading and thread management.
"""
import os
import logging
import time

logger = logging.getLogger(__name__)

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    from sentence_transformers import SentenceTransformer, util
    ML_AVAILABLE = True
except ImportError as e:
    logger.warning(f"ML Import Verification Failed: {e}")
    ML_AVAILABLE = False
    # Mock torch for type hints or simple usage if needed, or just skip
    torch = None

from typing import Dict, Any, List, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

if ML_AVAILABLE:
    class LocalMLEngine:
        _instance = None
        _models: Dict[str, Any] = {}
        _tokenizers: Dict[str, Any] = {}
        
        # Model Registry
        MODELS = {
            "dlp": "distilbert-base-uncased", # Will fine-tune or use zero-shot logic
            "malware": "distilbert-base-uncased", 
            "code": "microsoft/codebert-base",
            "zero_shot": "all-MiniLM-L6-v2" # Good default for sentence similarity
        }

        def __new__(cls):
            if cls._instance is None:
                cls._instance = super(LocalMLEngine, cls).__new__(cls)
                cls._instance._initialize()
            return cls._instance

        def _initialize(self):
            """Setup CPU optimizations."""
            # Force CPU
            self.device = torch.device("cpu")
            
            # CPU Thread Pinning (prevent hoarding)
            torch.set_num_threads(2) 
            torch.set_num_interop_threads(1)
            
            logger.info("LocalMLEngine initialized on CPU with limited threads.")

        def get_model(self, task: str):
            """Lazy load model for specific task."""
            if task not in self.MODELS:
                raise ValueError(f"Unknown task: {task}")
                
            model_name = self.MODELS[task]
            
            if task not in self._models:
                logger.info(f"Loading model for {task}: {model_name}...")
                start_time = time.time()
                
                try:
                    # Check for local offline model
                    safe_name = model_name.replace("/", "_")
                    local_path = os.path.join("models", safe_name)
                    
                    path_to_load = local_path if os.path.exists(local_path) else model_name
                    if path_to_load == local_path:
                        logger.info(f"files found at {local_path}, loading from local storage.")
                    
                    if task == "zero_shot":
                         # Load as SentenceTransformer
                         self._models[task] = SentenceTransformer(path_to_load, device='cpu')
                    else:
                        # Load Tokenizer
                        self._tokenizers[task] = AutoTokenizer.from_pretrained(path_to_load)
                        
                        # Load Model (Quantized/Optimized if possible)
                        self._models[task] = AutoModelForSequenceClassification.from_pretrained(
                            path_to_load, 
                            num_labels=2 # Default, adjusted per task logic
                        ).to(self.device)
                        self._models[task].eval() # Inference mode
                    
                    logger.info(f"Model loaded in {time.time() - start_time:.2f}s")
                except Exception as e:
                    logger.error(f"Failed to load model {model_name}: {e}")
                    raise
    
            # Return both (or just model if no tokenizer needed)
            tokenizer = self._tokenizers.get(task)
            return self._models[task], tokenizer
    
        def classify_text(self, task: str, text: str, labels: List[str]) -> Dict[str, Any]:
            """
            Generic text classification. 
            For zero-shot logic with base models, we might need mapped heads or pipelines.
            For now, this assumes a classification head matches the labels count or we use a zero-shot pipeline.
            
            To keep it deterministic & simple for Phase 1, we return raw scores normalized.
            """
            model, tokenizer = self.get_model(task)
            
            # Truncate to max length
            inputs = tokenizer(
                text, 
                return_tensors="pt", 
                truncation=True, 
                max_length=512,
                padding=True
            ).to(self.device)
            
            with torch.no_grad():
                outputs = model(**inputs)
                probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
                
            # Mock mapping for base models until fine-tuned
            # In real implementation, we'd load a specifically trained head
            confidence, predicted_idx = torch.max(probs, dim=1)
            
            return {
                "label_index": predicted_idx.item(),
                "confidence": confidence.item(),
                "logits": probs.tolist()[0]
            }
    
        def warmup(self):
            """Warm up models to prevent latency on first user request."""
            logger.info("Warming up ML Message...")
            try:
                self.compute_similarity("test warmup", ["safe", "unsafe"])
            except:
                pass
    
        def compute_similarity(self, text: str, labels: List[str]) -> Dict[str, Any]:
            """
            Zero-shot classification via semantic similarity using SentenceTransformer.
            Returns label with highest similarity score.
            """
            try:
                model, _ = self.get_model("zero_shot")
                
                # Encode text and labels
                text_emb = model.encode(text, convert_to_tensor=True)
                # We cache label embeddings in a real app, but for now encode on fly
                label_embs = model.encode(labels, convert_to_tensor=True)
                
                # Compute cosine similarity
                scores = util.cos_sim(text_emb, label_embs)[0]
                
                # Find best match
                best_score_idx = torch.argmax(scores).item()
                best_score = scores[best_score_idx].item()
                
                return {
                    "label": labels[best_score_idx],
                    "confidence": best_score,
                    "all_scores": {l: s.item() for l, s in zip(labels, scores)}
                }
            except Exception as e:
                logger.error(f"Compute similarity failed: {e}")
                return {"label": "UNKNOWN", "confidence": 0.0}

else:
    class MockMLEngine:
        def __init__(self):
            logger.warning("ML Dependencies missing. Providing Mock ML Engine.")
            
        def compute_similarity(self, text: str, labels: List[str]) -> Dict[str, Any]:
             # Simple keyword heuristic fallback
             text_lower = text.lower()
             best_label = "safe non-sensitive code documentation"
             confidence = 0.95
             
             if "password" in text_lower or "credential" in text_lower or "key" in text_lower:
                 best_label = "actionable production credential secret key"
             elif "eval(" in text_lower or "exec(" in text_lower or "pickle" in text_lower:
                 best_label = "vulnerable unsafe code execution exploit"
             elif "test" in text_lower or "example" in text_lower:
                 best_label = "dummy example data placeholder for testing"
                 
             return {
                "label": best_label,
                "confidence": confidence,
                "all_scores": {}
            }
            
        def classify_text(self, *args, **kwargs):
             return {"label_index": 0, "confidence": 0.0}
             
        def warmup(self):
             pass

# Global accessor
def get_ml_engine():
    if ML_AVAILABLE:
        return LocalMLEngine()
    else:
        return MockMLEngine()

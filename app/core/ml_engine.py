
"""
Local ML Engine
Single entry point for all local model inference (CPU optimized).
Wraps HuggingFace transformers with efficient loading and thread management.
"""
import os
import logging
import time
import threading

logger = logging.getLogger(__name__)

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    from sentence_transformers import SentenceTransformer, util
    ML_AVAILABLE = True
except ImportError as e:
    logger.warning(f"ML Import Verification Failed: {e}")
    ML_AVAILABLE = False
    torch = None

from typing import Dict, Any, List, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

if ML_AVAILABLE:
    class LocalMLEngine:
        _instance = None
        _lock = threading.Lock()
        _models: Dict[str, Any] = {}
        _tokenizers: Dict[str, Any] = {}

        # Model Registry
        MODELS = {
            "dlp": "distilbert-base-uncased",
            "malware": "distilbert-base-uncased",
            "code": "microsoft/codebert-base",
            # We use a fast, small NLI model by default for local dev/testing.
            # In production (8+ cores or GPU), you can replace this with:
            # "MoritzLaurer/deberta-v3-large-zeroshot-v2" or "facebook/bart-large-mnli"
            "zero_shot": "cross-encoder/nli-deberta-v3-small"
        }

        def __new__(cls):
            with cls._lock:
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
                        # Load as a proper zero-shot classification pipeline
                        from transformers import pipeline
                        self._models[task] = pipeline("zero-shot-classification", model=path_to_load, device=self.device)
                    else:
                        # Load Tokenizer
                        self._tokenizers[task] = AutoTokenizer.from_pretrained(path_to_load)

                        # Load Model (Quantized/Optimized if possible)
                        self._models[task] = AutoModelForSequenceClassification.from_pretrained(
                            path_to_load,
                            num_labels=2
                        ).to(self.device)
                        self._models[task].eval()

                    logger.info(f"Model loaded in {time.time() - start_time:.2f}s")
                except Exception as e:
                    logger.error(f"Failed to load model {model_name}: {e}")
                    raise

            # Return both (or just model if no tokenizer needed)
            tokenizer = self._tokenizers.get(task)
            return self._models[task], tokenizer

        def classify_text(self, task: str, text: str, labels: List[str]) -> Dict[str, Any]:
            """Generic text classification."""
            model, tokenizer = self.get_model(task)

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

            confidence, predicted_idx = torch.max(probs, dim=1)

            return {
                "label_index": predicted_idx.item(),
                "confidence": confidence.item(),
                "logits": probs.tolist()[0]
            }

        def warmup(self):
            """Warm up models to prevent latency on first user request."""
            logger.info("Warming up ML engine...")
            try:
                self.zero_shot_classify("test warmup", ["safe", "unsafe"])
                logger.info("ML engine warmup complete.")
            except Exception as e:
                logger.error(f"ML warmup failed: {e}")

        def zero_shot_classify(self, text: str, labels: List[str]) -> Dict[str, Any]:
            """
            Zero-shot classification via NLI pipeline.
            Returns the top label, confidence, inference time, and all probability scores.
            """
            start_time = time.time()
            try:
                classifier, _ = self.get_model("zero_shot")

                result = classifier(text, candidate_labels=labels, multi_label=False)

                inference_time_ms = int((time.time() - start_time) * 1000)

                best_label = result['labels'][0]
                best_score = result['scores'][0]
                all_scores = {label: score for label, score in zip(result['labels'], result['scores'])}

                return {
                    "label": best_label,
                    "confidence": best_score,
                    "all_scores": all_scores,
                    "inference_time_ms": inference_time_ms
                }
            except Exception as e:
                logger.error(f"Zero-shot classification failed: {e}")
                fallback_time = int((time.time() - start_time) * 1000)
                return {
                    "label": "ERROR",
                    "confidence": 0.0,
                    "all_scores": {},
                    "inference_time_ms": fallback_time,
                    "error": True
                }

else:
    class MockMLEngine:
        def __init__(self):
            logger.warning("ML Dependencies missing. Providing Mock ML Engine.")

        def zero_shot_classify(self, text: str, labels: List[str]) -> Dict[str, Any]:
            start_time = time.time()
            text_lower = text.lower()
            best_label = "safe non-sensitive code documentation"
            confidence = 0.95

            if "password" in text_lower or "credential" in text_lower or "key" in text_lower:
                best_label = "data_exfiltration"
            elif "eval(" in text_lower or "exec(" in text_lower or "pickle" in text_lower:
                best_label = "insider_risk"
            elif "test" in text_lower or "example" in text_lower:
                best_label = "benign_business"

            inference_time_ms = int((time.time() - start_time) * 1000)
            return {
                "label": best_label,
                "confidence": confidence,
                "all_scores": {best_label: confidence},
                "inference_time_ms": inference_time_ms
            }

        def classify_text(self, *args, **kwargs):
            return {"label_index": 0, "confidence": 0.0, "logits": [1.0, 0.0]}

        def warmup(self):
            pass

# Global accessor
def get_ml_engine():
    if ML_AVAILABLE:
        return LocalMLEngine()
    else:
        return MockMLEngine()

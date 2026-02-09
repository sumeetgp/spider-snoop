
"""
Model Downloader
Downloads required models to local 'models/' directory for offline usage.
"""
import os
import shutil
from transformers import AutoTokenizer, AutoModelForSequenceClassification


MODELS_TO_DOWNLOAD = {
    "distilbert-base-uncased": "distilbert-base-uncased",
    "microsoft/codebert-base": "microsoft/codebert-base",
    "all-MiniLM-L6-v2": "sentence-transformers/all-MiniLM-L6-v2"
}

TARGET_DIR = "models"

def download_models():
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    for model_name, original_name in MODELS_TO_DOWNLOAD.items():
        safe_name = original_name.replace("/", "_") 
        # Hack for short name mapping if needed, but our engine expects "sentence-transformers_all-MiniLM-L6-v2" 
        # if logic in ml_engine uses replace('/', '_') on "sentence-transformers/all-MiniLM-L6-v2"
        # Wait, ml_engine.py uses: "zero_shot": "all-MiniLM-L6-v2"
        # So it looks for models/all-MiniLM-L6-v2
        
        # Let's align keys. 
        # ml_engine says: MODELS["zero_shot"] = "all-MiniLM-L6-v2"
        # it tries to load "models/all-MiniLM-L6-v2" (because replace doesn't do much if no slash)
        # OR "all-MiniLM-L6-v2" from hub.
        
        # SentenceTransformers usually live on Hub as "sentence-transformers/all-MiniLM-L6-v2"
        # But can be loaded by short name "all-MiniLM-L6-v2"
        
        # I will download to "models/all-MiniLM-L6-v2" to match ml_engine expectation
        
        if "MiniLM" in original_name:
             target_path = os.path.join(TARGET_DIR, "all-MiniLM-L6-v2")
             print(f"Downloading {original_name} to {target_path}...")
             if os.path.exists(target_path):
                 print(" - Already exists.")
                 continue
             
             try:
                 from sentence_transformers import SentenceTransformer
                 model = SentenceTransformer(original_name)
                 model.save(target_path)
                 print(" - Success!")
             except Exception as e:
                 print(f" - Failed: {e}")
             continue

        # Standard Transformers Logic
        safe_name = original_name.replace("/", "_") 
        model_path = os.path.join(TARGET_DIR, safe_name)
        
        print(f"Downloading {original_name} to {model_path}...")
        
        if os.path.exists(model_path):
            print(f" - {model_path} already exists. Skipping.")
            continue
            
        try:
            # Download Tokenizer
            tokenizer = AutoTokenizer.from_pretrained(original_name)
            tokenizer.save_pretrained(model_path)
            
            # Download Model
            model = AutoModelForSequenceClassification.from_pretrained(original_name)
            model.save_pretrained(model_path)
            
            print(f" - Success!")
        except Exception as e:
            print(f" - Failed: {e}")

if __name__ == "__main__":
    download_models()

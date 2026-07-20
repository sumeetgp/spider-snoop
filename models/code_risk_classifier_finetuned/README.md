---
tags:
- setfit
- sentence-transformers
- text-classification
- code-security
- dlp
- secret-detection
- vulnerability-detection
language:
- en
license: apache-2.0
widget:
- text: "Analyze this hardcoded_secret: AWS_ACCESS_KEY_ID=AKIA4REALKEY123ABC committed to main branch .env file"
- text: "Analyze this vulnerable_pattern: $query = 'SELECT * FROM users WHERE id=' . $_GET['id'];"
- text: "Analyze this test_fixture: factory_boy default: user.password = 'testpass123' for pytest fixtures"
- text: "Analyze this clean_code: def get_user(db: Session, user_id: int): return db.query(User).filter(User.id == user_id).first()"
- text: "Analyze this secure_implementation: password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))"
metrics:
- accuracy
pipeline_tag: text-classification
library_name: setfit
inference: true
model-index:
- name: spidercob/code-risk-classifier
  results:
  - task:
      type: text-classification
      name: Text Classification
    dataset:
      name: curated-public-repos-v2
      type: custom
      split: test
    metrics:
    - type: accuracy
      value: 1.0
      name: Accuracy
---

# spidercob/code-risk-classifier

A [SetFit](https://github.com/huggingface/setfit) model that classifies code snippets and secrets into four risk categories. Used inside [Spidercob](https://spidercob.com) to reduce false positives in supply-chain and secret scanning — distinguishing real production risks from test fixtures and safe code.

**v2** — expanded multi-language training corpus (22 public repos, Python / Java / PHP / JavaScript / TypeScript / Ruby / Go).

## Labels

| Label | Meaning | Action |
|---|---|---|
| `REAL_SECRET` | Hardcoded credential, API key, or token committed to source | **BLOCK** |
| `VULNERABLE_LOGIC` | SQL injection, XSS, unsafe deserialization, command injection, etc. | **BLOCK** |
| `TEST_MOCK` | Dummy credential or vuln pattern inside a test fixture or factory | ALLOW |
| `SAFE_CODE` | Clean production code, secure implementation pattern | ALLOW |

## Quick Start

```python
from setfit import SetFitModel

model = SetFitModel.from_pretrained("spidercob/code-risk-classifier")

snippets = [
    "Analyze this hardcoded_secret: AWS_ACCESS_KEY_ID=AKIA4REALKEY123ABC in .env",
    "Analyze this vulnerable_pattern: $q = 'SELECT * FROM users WHERE id=' . $_GET['id'];",
    "Analyze this test_fixture: user.password = 'testpass123'  # factory_boy default",
    "Analyze this clean_code: password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
]

predictions = model.predict(snippets)
probabilities = model.predict_proba(snippets)
# predictions: ['REAL_SECRET', 'VULNERABLE_LOGIC', 'TEST_MOCK', 'SAFE_CODE']
```

## Input Format

Inputs must follow the pattern used during training:

```
Analyze this <issue_type>: <code_snippet_or_context>
```

Where `<issue_type>` is a short descriptor such as `hardcoded_secret`, `vulnerable_pattern`, `test_fixture`, `clean_code`, `secure_implementation`, etc.

## Integration with Spidercob DLP

```python
from app.core.code_risk_classifier import CodeRiskClassifier

clf = CodeRiskClassifier()
result = clf.classify("hardcoded_secret", "STRIPE_SECRET_KEY = 'sk_live_abc123xyz'")
# result: {"risk_type": "REAL_SECRET", "confidence": 0.99, "action": "BLOCK", "severity": "CRITICAL"}
```

The classifier loads the fine-tuned SetFit model at import time and falls back to zero-shot cosine similarity if the model directory is absent.

## Evaluation

| Label   | Accuracy |
|:--------|:---------|
| **all** | **1.0** (100%, 176 test examples) |

## Training Details (v2)

### Dataset

877 labelled examples extracted from **22 curated public GitHub repositories** via regex-based heuristics. Each example is a 3–7 line context window around a matched line, formatted as `Analyze this <issue_type>: <context>`.

**Languages covered:** Python, Java, PHP, JavaScript, TypeScript, Ruby, Go

### Training Set Composition

| Label | Train examples | Source strategy |
|---|---|---|
| `REAL_SECRET` | 27 | TruffleHog test corpus (confirmed leaked secrets), Railsgoat, NodeGoat, Juice Shop |
| `VULNERABLE_LOGIC` | 194 | DVWA (PHP), WebGoat (Java), vulhub, NodeGoat, DVGA, Railsgoat, Juice Shop |
| `TEST_MOCK` | 240 | factory_boy, Faker, pytest, model_bakery |
| `SAFE_CODE` | 240 | Django, FastAPI, requests, Flask, httpx, Devise, Sinatra, Gin |

### Source Repositories

| Repo | Label | Language |
|---|---|---|
| OWASP/WebGoat | VULNERABLE_LOGIC | Java |
| digininja/DVWA | VULNERABLE_LOGIC | PHP |
| vulhub/vulhub | VULNERABLE_LOGIC | multi |
| trufflesecurity/trufflehog | REAL_SECRET | Go/multi |
| OWASP/NodeGoat | VULNERABLE_LOGIC | JavaScript |
| dolevf/Damn-Vulnerable-GraphQL-Application | VULNERABLE_LOGIC | Python |
| OWASP/railsgoat | VULNERABLE_LOGIC | Ruby |
| juice-shop/juice-shop | VULNERABLE_LOGIC | TypeScript |
| FactoryBoy/factory_boy | TEST_MOCK | Python |
| joke2k/faker | TEST_MOCK | Python |
| pytest-dev/pytest | TEST_MOCK | Python |
| model-bakers/model_bakery | TEST_MOCK | Python |
| django/django | SAFE_CODE | Python |
| tiangolo/fastapi | SAFE_CODE | Python |
| psf/requests | SAFE_CODE | Python |
| pallets/flask | SAFE_CODE | Python |
| encode/httpx | SAFE_CODE | Python |
| heartcombo/devise | SAFE_CODE | Ruby |
| sinatra/sinatra | SAFE_CODE | Ruby |
| gin-gonic/gin | SAFE_CODE | Go |
| golang/vulndb | VULNERABLE_LOGIC | Go |

### Training Hyperparameters
- batch_size: (16, 16)
- num_epochs: (3, 3)
- max_steps: -1
- sampling_strategy: oversampling
- num_iterations: 20
- body_learning_rate: (2e-05, 1e-05)
- head_learning_rate: 0.01
- loss: CosineSimilarityLoss
- distance_metric: cosine_distance
- margin: 0.25
- end_to_end: False
- use_amp: False
- warmup_proportion: 0.1
- l2_weight: 0.01
- seed: 42
- eval_max_steps: -1
- load_best_model_at_end: True

### Training Results
| Epoch  | Step | Training Loss | Validation Loss |
|:------:|:----:|:-------------:|:---------------:|
| 0.0006 | 1    | 0.0416        | -               |
| 0.0285 | 50   | 0.0099        | -               |
| 0.0570 | 100  | 0.0028        | -               |
| 0.0856 | 150  | 0.001         | -               |
| 0.1141 | 200  | 0.0013        | -               |
| 0.1426 | 250  | 0.0003        | -               |
| 0.1711 | 300  | 0.0002        | -               |
| 0.1997 | 350  | 0.0002        | -               |
| 0.2282 | 400  | 0.0002        | -               |
| 0.2567 | 450  | 0.0002        | -               |
| 0.2852 | 500  | 0.0002        | -               |
| 0.3137 | 550  | 0.0001        | -               |
| 0.3423 | 600  | 0.0001        | -               |
| 0.3708 | 650  | 0.0001        | -               |
| 0.3993 | 700  | 0.0001        | -               |
| 0.4278 | 750  | 0.0001        | -               |
| 0.4564 | 800  | 0.0001        | -               |
| 0.4849 | 850  | 0.0001        | -               |
| 0.5134 | 900  | 0.0001        | -               |
| 0.5419 | 950  | 0.0001        | -               |
| 0.5705 | 1000 | 0.0001        | -               |
| 0.5990 | 1050 | 0.0001        | -               |
| 0.6275 | 1100 | 0.0001        | -               |
| 0.6560 | 1150 | 0.0001        | -               |
| 0.6845 | 1200 | 0.0001        | -               |
| 0.7131 | 1250 | 0.0001        | -               |
| 0.7416 | 1300 | 0.0001        | -               |
| 0.7701 | 1350 | 0.0001        | -               |
| 0.7986 | 1400 | 0.0           | -               |
| 0.8272 | 1450 | 0.0001        | -               |
| 0.8557 | 1500 | 0.0001        | -               |
| 0.8842 | 1550 | 0.0           | -               |
| 0.9127 | 1600 | 0.0           | -               |
| 0.9412 | 1650 | 0.0001        | -               |
| 0.9698 | 1700 | 0.0           | -               |
| 0.9983 | 1750 | 0.0           | -               |
| 1.0    | 1753 | -             | 0.0001          |
| 1.0268 | 1800 | 0.0           | -               |
| 1.0553 | 1850 | 0.0           | -               |
| 1.0839 | 1900 | 0.0           | -               |
| 1.1124 | 1950 | 0.0           | -               |
| 1.1409 | 2000 | 0.0           | -               |
| 1.1694 | 2050 | 0.0           | -               |
| 1.1979 | 2100 | 0.0           | -               |
| 1.2265 | 2150 | 0.0           | -               |
| 1.2550 | 2200 | 0.0           | -               |
| 1.2835 | 2250 | 0.0           | -               |
| 1.3120 | 2300 | 0.0           | -               |
| 1.3406 | 2350 | 0.0           | -               |
| 1.3691 | 2400 | 0.0           | -               |
| 1.3976 | 2450 | 0.0           | -               |
| 1.4261 | 2500 | 0.0           | -               |
| 1.4546 | 2550 | 0.0           | -               |
| 1.4832 | 2600 | 0.0           | -               |
| 1.5117 | 2650 | 0.0           | -               |
| 1.5402 | 2700 | 0.0           | -               |
| 1.5687 | 2750 | 0.0           | -               |
| 1.5973 | 2800 | 0.0           | -               |
| 1.6258 | 2850 | 0.0           | -               |
| 1.6543 | 2900 | 0.0           | -               |
| 1.6828 | 2950 | 0.0           | -               |
| 1.7114 | 3000 | 0.0           | -               |
| 1.7399 | 3050 | 0.0           | -               |
| 1.7684 | 3100 | 0.0           | -               |
| 1.7969 | 3150 | 0.0           | -               |
| 1.8254 | 3200 | 0.0           | -               |
| 1.8540 | 3250 | 0.0           | -               |
| 1.8825 | 3300 | 0.0           | -               |
| 1.9110 | 3350 | 0.0           | -               |
| 1.9395 | 3400 | 0.0           | -               |
| 1.9681 | 3450 | 0.0           | -               |
| 1.9966 | 3500 | 0.0           | -               |
| 2.0    | 3506 | -             | 0.0000          |
| 2.0251 | 3550 | 0.0           | -               |
| 2.0536 | 3600 | 0.0           | -               |
| 2.0821 | 3650 | 0.0           | -               |
| 2.1107 | 3700 | 0.0           | -               |
| 2.1392 | 3750 | 0.0           | -               |
| 2.1677 | 3800 | 0.0           | -               |
| 2.1962 | 3850 | 0.0           | -               |
| 2.2248 | 3900 | 0.0           | -               |
| 2.2533 | 3950 | 0.0           | -               |
| 2.2818 | 4000 | 0.0           | -               |
| 2.3103 | 4050 | 0.0           | -               |
| 2.3388 | 4100 | 0.0           | -               |
| 2.3674 | 4150 | 0.0           | -               |
| 2.3959 | 4200 | 0.0           | -               |
| 2.4244 | 4250 | 0.0           | -               |
| 2.4529 | 4300 | 0.0           | -               |
| 2.4815 | 4350 | 0.0           | -               |
| 2.5100 | 4400 | 0.0           | -               |
| 2.5385 | 4450 | 0.0           | -               |
| 2.5670 | 4500 | 0.0           | -               |
| 2.5956 | 4550 | 0.0           | -               |
| 2.6241 | 4600 | 0.0           | -               |
| 2.6526 | 4650 | 0.0           | -               |
| 2.6811 | 4700 | 0.0           | -               |
| 2.7096 | 4750 | 0.0           | -               |
| 2.7382 | 4800 | 0.0           | -               |
| 2.7667 | 4850 | 0.0           | -               |
| 2.7952 | 4900 | 0.0           | -               |
| 2.8237 | 4950 | 0.0           | -               |
| 2.8523 | 5000 | 0.0           | -               |
| 2.8808 | 5050 | 0.0           | -               |
| 2.9093 | 5100 | 0.0           | -               |
| 2.9378 | 5150 | 0.0           | -               |
| 2.9663 | 5200 | 0.0           | -               |
| 2.9949 | 5250 | 0.0           | -               |
| 3.0    | 5259 | -             | 0.0000          |

### Framework Versions
- Python: 3.12.12
- SetFit: 1.1.3
- Sentence Transformers: 5.2.2
- Transformers: 4.57.6
- PyTorch: 2.10.0
- Datasets: 5.0.0
- Tokenizers: 0.22.2

## Citation

### BibTeX
```bibtex
@article{https://doi.org/10.48550/arxiv.2209.11055,
    doi = {10.48550/ARXIV.2209.11055},
    url = {https://arxiv.org/abs/2209.11055},
    author = {Tunstall, Lewis and Reimers, Nils and Jo, Unso Eun Seo and Bates, Luke and Korat, Daniel and Wasserblat, Moshe and Pereg, Oren},
    keywords = {Computation and Language (cs.CL), FOS: Computer and information sciences, FOS: Computer and information sciences},
    title = {Efficient Few-Shot Learning Without Prompts},
    publisher = {arXiv},
    year = {2022},
    copyright = {Creative Commons Attribution 4.0 International}
}
```

<!--
## Glossary

*Clearly define terms in order to be accessible across audiences.*
-->

<!--
## Model Card Authors

*Lists the people who create the model card, providing recognition and accountability for the detailed work that goes into its construction.*
-->

<!--
## Model Card Contact

*Provides a way for people who have updates to the Model Card, suggestions, or questions, to contact the Model Card authors.*
-->
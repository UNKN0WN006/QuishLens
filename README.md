# QuishLens

**Multimodal pre-click QR phishing analysis for images, screenshots, PDFs, and URLs.**

QuishLens is a cybersecurity prototype designed for people who receive QR codes in email, documents, posters, screenshots, payment messages, or account notices and want to inspect the destination **before opening it**. It combines QR extraction, static URL analysis, optional machine-learning classification, brand/domain mismatch checks, local threat intelligence, document-text/NLP signals, deterministic risk scoring, and two levels of explanation: a technical evidence view and a plain-language view.

> QuishLens does not intentionally navigate to decoded destinations. Treat all threat feeds and malicious samples as untrusted research data.

## Why this project exists

A QR code hides a destination from the eye. A user can see a familiar logo or a message saying “verify your account,” but cannot easily inspect the URL encoded inside the QR. QuishLens turns that hidden destination into explicit, testable evidence.

The project is deliberately **not** an “ask an AI if this is phishing” wrapper. The final risk score is deterministic and based on inspectable signals. Machine learning is one input, not the authority.

## What is implemented

- Drag-and-drop web UI for PNG, JPG, WEBP, BMP, and PDF
- QR detection/decoding with OpenCV and several image fallbacks
- PDF page rendering and text extraction with PyMuPDF
- Static URL feature extraction (22 model features + descriptive fields)
- Random Forest model support via `joblib`
- Transparent heuristic fallback when no trained model is installed
- Brand/domain mismatch and lookalike detection for common global and Indian brands
- Local threat-intelligence URL/domain snapshots
- Lightweight NLP/context analysis for urgency, credentials, payment pressure, threats, QR calls-to-action, and brand mentions
- Deterministic 0–100 risk engine with evidence contributions
- Plain-language mode for non-technical adults/young users
- Evidence popup/modal, health popup, session scan history, responsive UI
- Generic model-training script for arbitrary CSV URL/label columns
- Independent URL benchmark adapter
- QR image-manifest benchmark adapter
- PDF/image document-manifest benchmark adapter
- Adversarial QR transformations (rotation, blur, JPEG compression, scaling, contrast, noise)
- Threat-feed importer
- Safe local demo QR images/PDF using reserved `.invalid` domains
- Automated tests

## Run locally

Python 3.11+ is recommended.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
python scripts/generate_demo_samples.py
python scripts/bootstrap_demo_model.py
./run.sh
```

On Windows, run:

```powershell
python -m uvicorn app.main:app --reload --port 8000
```

Open `http://127.0.0.1:8000`.

The built-in bootstrap model is **only for demonstrating the ML integration**. Train on a real, documented phishing dataset before quoting model performance in a submission.

## One-command Docker option

```bash
docker build -t quishlens .
docker run --rm -p 8000:8000 quishlens
```

## Architecture

```text
Image / screenshot ─┐
PDF ────────────────┼─> QR extraction ─> decoded payload ─┐
Direct URL ─────────┘                                     │
                                                          ├─> URL feature engine
PDF text ─────────────────────────────────────────────────┼─> context/NLP signals
                                                          ├─> brand/domain checks
Local threat feed ────────────────────────────────────────┼─> threat-intel match
Optional RF model ────────────────────────────────────────┘
                                                                   │
                                                           deterministic risk engine
                                                                   │
                                                       technical + plain explanation
```

## Main source layout

```text
app/
  main.py                 FastAPI routes + static frontend
  service.py              analysis orchestration
  scanner/
    qr_detector.py         OpenCV QR extraction
    pdf_scanner.py         PDF rendering/text extraction
    file_scanner.py        file dispatch
  analysis/
    url_features.py        model + descriptive URL features
    brand_detector.py      brand/domain mismatch
    context_nlp.py         lightweight document-language analysis
    threat_intel.py        local feed lookup
    model_service.py       trained model / heuristic fallback
    risk_engine.py         deterministic score
    explain.py             evidence-grounded explanations
  static/
    index.html
    styles.css
    app.js
scripts/
  train_url_model.py
  evaluate_url_dataset.py
  evaluate_qr_manifest.py
  evaluate_pdf_manifest.py
  adversarial_qr_test.py
  import_threat_feed.py
  generate_demo_samples.py
  bootstrap_demo_model.py
```

## Train on a real URL dataset

The training adapter does not assume a fixed schema.

```bash
python scripts/train_url_model.py \
  --csv /path/to/train.csv \
  --url-column url \
  --label-column label \
  --positive-label phishing
```

If labels are already `0/1`, omit `--positive-label`.

The model is written to:

```text
app/models/url_classifier.joblib
app/models/url_classifier.meta.json
```

Restart QuishLens or call `POST /api/reload`.

## Independent URL evaluation

**Do not retrain on the external benchmark.**

```bash
python scripts/evaluate_url_dataset.py \
  --csv /path/to/PhiUSIIL.csv \
  --url-column URL \
  --label-column label \
  --positive-label phishing \
  --name PhiUSIIL
```

The evaluator writes per-sample predictions and updates `results/benchmark_summary.json`, which the UI's **Benchmarks** page reads.

Reported metrics include accuracy, precision, recall, F1, ROC-AUC, false-positive rate, false-negative rate, average latency, and p95 latency.

## QR dataset evaluation

Create a manifest such as:

```csv
path,label
benign/0001.png,0
benign/0002.png,0
phishing/0001.png,1
phishing/0002.png,1
```

Run:

```bash
python scripts/evaluate_qr_manifest.py \
  --manifest /dataset/manifest.csv \
  --root /dataset \
  --path-column path \
  --label-column label \
  --name CIC-Trap4Phish-QR
```

This intentionally reports **QR decode rate separately from phishing classification metrics**. A detector cannot classify a QR payload it failed to decode, and hiding that distinction would inflate the apparent quality of the system.

## PDF/document benchmark

Manifest format is the same (`path,label`).

```bash
python scripts/evaluate_pdf_manifest.py \
  --manifest /dataset/pdf_manifest.csv \
  --root /dataset \
  --name CIC-Trap4Phish-PDF
```

This reports classification metrics, rate of documents containing decoded QR codes, and processing-failure rate. For general parser corpora such as SafeDocs/UNSAFE-DOCS, use the processing-failure statistic rather than pretending those datasets have phishing ground truth.

## Adversarial QR robustness

```bash
python scripts/adversarial_qr_test.py --image data/demo/suspicious_qr.png
```

Current transformations:

- original
- rotation 15° / 45°
- Gaussian blur
- 50% downscale/upscale
- JPEG quality 35
- low contrast
- additive image noise

The result measures **decode robustness**, not maliciousness.

## Load a downloaded threat feed

QuishLens never needs to visit a malicious URL to use a threat feed.

One URL per line:

```bash
python scripts/import_threat_feed.py --input downloaded_feed.txt
```

CSV:

```bash
python scripts/import_threat_feed.py \
  --input phishtank.csv \
  --url-column url
```

Then restart or `POST /api/reload`.

**Do not commit live malicious URLs into a public repository.** Keep feeds local and cite the provider in your methodology.

## Recommended evaluation matrix

Keep datasets separate by what they actually test:

| Family | What QuishLens should measure |
|---|---|
| CIC-Trap4Phish QR | QR decode rate + phishing classification |
| Trad/Chehab QR | Cross-dataset QR structural/decode generalization |
| BanglaQR-Quish | Payment-QR generalization |
| PhiUSIIL | Independent URL classification |
| ISCX-URL2016 | Phishing vs broader malicious URL behavior |
| PhishTank/OpenPhish snapshot | Fresh phishing recall |
| Tranco | False positives on popular legitimate domains |
| CIC-Trap4Phish PDF | Quishing attachment detection |
| CIC-Evasive-PDFMal2022 | PDF parser/feature robustness (not necessarily quishing) |
| SafeDocs | Ordinary PDF processing robustness |
| UNSAFE-DOCS | Malformed/adversarial PDF processing robustness |
| NIST CFReDS / Digital Corpora | Future forensic artifact recovery, reported separately |

## Risk score

The runtime score combines:

- URL classifier: up to 35
- threat-intelligence match: 30
- brand/domain mismatch: 15
- structural URL warnings: supporting points
- social-engineering context: supporting points

Thresholds:

```text
0–29   LOW
30–59  SUSPICIOUS
60–79  HIGH
80–100 CRITICAL
```

These are prototype policy thresholds, **not calibrated probabilities**. Tune them using validation data and document any changes.

## Child/adult-friendly behavior

Plain-language mode intentionally avoids jargon. High-risk guidance says not to enter passwords/OTPs or send money, and suggests opening the organisation's official app/site independently. It does not claim that a low-risk result guarantees safety.

For a public deployment, add a real privacy policy, retention controls, server-side malware sandboxing for hostile documents, content-security headers, rate limiting, audit logging, and a reviewed accessibility pass.

## Safety and limitations

- Static analysis reduces exposure but cannot prove a site is harmless.
- The lightweight registered-domain function is not a full Public Suffix List implementation. Swap in a PSL library for production.
- Brand rules are intentionally small and auditable; they are not an exhaustive brand database.
- PDF files can be hostile. A production scanner should process them in a hardened sandbox/container with strict resource limits.
- URL classifier performance depends entirely on training data quality and drift.
- No benchmark result should be quoted unless the exact dataset, sample selection, split, model version, and threshold are recorded.
- Threat-intelligence absence is not evidence of safety.
- Do not fetch or execute malicious payloads while benchmarking.

## Demo flow

1. Generate samples: `python scripts/generate_demo_samples.py`
2. Open QuishLens.
3. Upload `data/demo/suspicious_notice.pdf`.
4. Show QR extraction + decoded `.invalid` URL + brand mismatch + contextual urgency + local demo threat-intel match.
5. Upload `data/demo/benign_qr.png`.
6. Show the lower-risk control.
7. Open Benchmarks and show metrics from a real external evaluation.
8. Run the adversarial script and discuss where QR decoding fails.

## Tests

```bash
pytest -q
```

The test suite covers URL features, brand mismatch, context signals, deterministic risk scoring, and QR round-trip decoding.

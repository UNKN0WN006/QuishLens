# QuishLens

**Tiny square. Big trust problem.**

QR codes are wonderfully convenient and slightly ridiculous: a box of black squares can quietly contain a website, a payment instruction, Wi-Fi credentials, a phone number, an authenticator secret, or just plain text — and most people only find out *after* their phone decides what to do with it.

QuishLens exists for the little moment before that.

It reads QR codes from images, screenshots, and PDFs, explains what the QR actually contains, and then applies the right safety checks for that payload. A website QR is analysed like a website. A payment QR is parsed like a payment QR. Wi-Fi credentials are treated like credentials. A QR that just contains text is shown as text instead of being forced through a phishing-URL classifier wearing a fake moustache.

> QuishLens performs static inspection and does not intentionally browse to decoded destinations.

## The fun-sized version

1. Drop in a QR image, screenshot, or PDF.
2. QuishLens decodes **QR symbols only** — ordinary 1D barcodes are ignored.
3. It identifies what the QR contains.
4. The relevant security checks run.
5. You get a human-readable explanation before you click, pay, join, call, send, or save anything.

There is also a direct **Check a link** mode when the QR has already been decoded somewhere else.

## What it understands now

QuishLens does not assume every QR is a URL. It recognises and explains:

- HTTP/HTTPS links
- EMV-style merchant payment QR payloads
- UPI payment links
- Wi-Fi configuration QR codes
- vCard/contact QR codes
- email actions
- SMS actions
- telephone numbers
- geographic coordinates
- OTP/authenticator setup secrets
- plain text and custom/application payloads

For links, it can also expose URLs embedded inside common redirect parameters **without following the redirect over the network**.

## QR decoding: more stubborn than before

The first version relied mostly on OpenCV. That worked nicely on many QR codes, but not all perfectly valid ones.

The current scanner uses three independent QR paths:

1. **ZXing-C++**, restricted to QR format when the binding supports format selection, for stylised and difficult symbols.
2. **ZBar/pyzbar, restricted to `QRCODE` symbols only**, for fast decoding of many clean QR images.
3. **OpenCV QRCodeDetector** plus quiet-zone padding, grayscale, upscaling, thresholding, contrast, inversion, and rotation fallbacks.

The Runtime panel reports which decoders are actually available on the current machine, so a missing native dependency is visible instead of silently weakening the scanner.

This matters in real datasets. On a 200-image random development sample from the supplied BanglaQR-Quish archive, OpenCV alone decoded 185/200 images while the QR-only ZBar path decoded all 200. That is a decoder engineering check, not a phishing-accuracy claim.

## Payment QR analysis

This is one of the biggest changes.

If a QR contains an EMV-style payment payload, QuishLens parses its tag-length-value structure and can expose useful fields such as:

- merchant name
- merchant city
- country
- currency
- requested amount, if fixed
- merchant category code
- payment provider identifier
- account-template structure
- checksum/CRC validity

It also looks for unusual things such as a **web address replacing a payment-provider identifier**.

A valid checksum does **not** prove that the receiver is trustworthy. It only proves that the structured payload is internally consistent. QuishLens says that explicitly instead of treating “valid QR” as “safe QR”.

## BanglaQR-Quish support

The repository now includes tooling specifically for the provided **BanglaQR-Quish** research dataset. The dataset contains 50,000 synthetic payment QR images split evenly between benign and malicious samples, including:

- provider GUI/URL injection
- payment redirection

The evaluator can read the outer dataset ZIP and the nested `benign.zip` / `malicious.zip` files directly, so it does **not** need to explode 50,000 PNG files onto disk.

```bash
python scripts/evaluate_banglaqr_zip.py \
  "/path/to/BanglaQR-Quish A Balanced Synthetic QR Image Datas.zip" \
  --limit-per-class 1000
```

It reports:

- QR decode rate
- payment-payload recognition rate
- accuracy / precision / recall / F1
- confusion matrix
- recall by attack type
- sample explanations

### Optional payment-QR anomaly model

The current repository also includes a small research model trained from a development sample of BanglaQR-Quish. It uses structural payment-payload features such as provider-identifier shape, account-field structure, entropy, repeated-character runs, payload length, checksum state, and embedded URL indicators.

It deliberately does **not** use image filenames, dataset labels as features, or exact hard-coded attacker strings.

The included model metadata marks it as **research-only**. Its internal hold-out numbers describe this synthetic dataset only; they are not evidence that it generalises to every real bKash/Nagad/merchant QR in the world.

Retrain it yourself with:

```bash
python scripts/train_banglaqr_payment_model.py \
  "/path/to/BanglaQR-Quish A Balanced Synthetic QR Image Datas.zip" \
  --per-attack 1000
```

## Website/link analysis

For normal web links, QuishLens combines:

- lexical URL features
- registered-domain approximation
- IP-address detection
- punycode indicators
- URL-shortener detection
- suspicious token analysis
- subdomain depth
- entropy and length signals
- brand/domain mismatch checks
- local threat-intelligence matches
- optional Random Forest URL classifier
- nearby document/social-engineering context

The final risk score is deterministic and inspectable. The ML model contributes evidence; it is not allowed to magically declare something evil with no explanation.

## Simple view actually changes the app now

The site starts in **Simple view** because the intended audience includes ordinary adults and younger users, not only security people.

Simple view hides:

- classifier percentages
- raw evidence lists
- benchmark tooling
- implementation/method pages
- raw PDF/context internals
- model/runtime details

It keeps:

- what the QR contains
- merchant/payee information
- risk level
- plain-language explanation
- practical next steps

Switch to **Detailed view** and all the technical evidence appears again.

## Frontend direction

The frontend was intentionally moved away from the very common “AI dashboard” look.

There is no purple/blue AI gradient, chatbot panel, glowing orb, or fake futuristic HUD. The current interface uses a muted forensic/safety palette, centred product heading, horizontal navigation, translucent glass panels, and a small opening animation that shows the actual product idea:

```text
QR  ->  decoded content  ->  explanation
```

When the site opens, it immediately asks whether you want to inspect:

- a QR/image/PDF
- an already-decoded link

The animation is CSS/HTML, not an external stock GIF, so the UI stays lightweight and self-contained.

## Architecture

```text
                    IMAGE / SCREENSHOT / PDF
                               │
                               ▼
                       QR-only decoding
                    ZBar QR -> OpenCV fallback
                               │
                               ▼
                        Payload classifier
                               │
          ┌────────────────────┼─────────────────────┐
          │                    │                     │
          ▼                    ▼                     ▼
       Web URL              Payment QR          Other payload
          │                    │              Wi-Fi / contact /
          │                    │              SMS / OTP / text
          ▼                    ▼                     │
 URL / brand / ML      TLV + CRC + provider          │
 threat-intel checks   + payment anomaly model       │
          │                    │                     │
          └────────────────────┴─────────────────────┘
                               │
                               ▼
                       explainable risk
                               │
                       simple / detailed UI
```

## Main source map

```text
app/
  main.py                       FastAPI routes and web app
  service.py                    analysis orchestration
  schemas.py                    API response models
  config.py                     paths and safety limits

  scanner/
    qr_detector.py              QR-only decoding + fallbacks
    pdf_scanner.py              embedded-image and rendered-page scanning
    file_scanner.py             file dispatch

  analysis/
    qr_payload.py               QR payload classification + EMV/UPI parsing
    payment_features.py         payment-model feature extraction
    payment_model.py            optional payment QR anomaly model
    url_features.py             URL feature extraction
    model_service.py            URL model + transparent fallback
    brand_detector.py           brand/domain mismatch detection
    threat_intel.py             local threat snapshot lookup
    context_nlp.py              lightweight social-engineering language analysis
    risk_engine.py              URL risk contributions
    explain.py                  grounded explanations

  static/
    index.html                  interface structure
    styles.css                  custom glass/safety visual system
    app.js                      interactions, modes, dialogs, rendering

scripts/
  train_url_model.py
  evaluate_url_dataset.py
  evaluate_qr_manifest.py
  evaluate_pdf_manifest.py
  evaluate_banglaqr_zip.py
  train_banglaqr_payment_model.py
  adversarial_qr_test.py
  import_threat_feed.py
  generate_demo_samples.py
  bootstrap_demo_model.py
```

## Run locally

Python 3.11+ is recommended.

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

Or simply use:

```text
run.bat
```

Then open:

```text
http://127.0.0.1:8000
```

### Linux / macOS

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./run.sh
```

## Docker

The Docker image installs `libzbar0` because the secondary QR decoder requires the ZBar runtime.

```bash
docker build -t quishlens .
docker run --rm -p 8000:8000 quishlens
```

## Train a URL model

```bash
python scripts/train_url_model.py \
  --csv /path/to/train.csv \
  --url-column url \
  --label-column label \
  --positive-label phishing
```

The app automatically falls back to transparent URL heuristics if no model is available.

## Generic QR benchmark

For other QR datasets, create a manifest:

```csv
path,label
benign/0001.png,0
benign/0002.png,0
phishing/0001.png,1
```

Then run:

```bash
python scripts/evaluate_qr_manifest.py \
  --manifest /dataset/manifest.csv \
  --root /dataset \
  --name My-QR-Benchmark
```

QuishLens reports decoding separately from classification so a failed decoder cannot quietly disappear from the accuracy number.

## PDF benchmark

```bash
python scripts/evaluate_pdf_manifest.py \
  --manifest /dataset/pdf_manifest.csv \
  --root /dataset \
  --name CIC-Trap4Phish-PDF
```

## Adversarial QR robustness

```bash
python scripts/adversarial_qr_test.py --image data/demo/suspicious_qr.png
```

Current transformations include rotation, blur, resizing, JPEG compression, low contrast, and image noise.

## Important limitation that I do not want to hide

A payment QR can be perfectly structured, have a valid checksum, contain a legitimate provider identifier, and still point to the wrong receiving account.

That means “parse the QR” and “prove the payee is honest” are not the same problem.

QuishLens currently tackles that in three ways:

1. show the actual payment fields so the person can verify them;
2. compare surrounding document context when available;
3. optionally use a payment-anomaly research model as supporting evidence.

A stronger future version would add a trusted-payee baseline or bank/provider verification source rather than pretending this limitation does not exist.

## Safety

- decoded URLs are analysed as strings;
- QuishLens does not intentionally navigate to suspicious destinations;
- threat feeds should stay local and should not be committed to a public repository;
- QR authenticator secrets are not displayed in the friendly structured view;
- Wi-Fi passwords are hidden in the structured view;
- raw decoded content is available only in Detailed view because sometimes forensic work really does need the ugly bits;
- uploaded file bytes are processed in memory and are not deliberately written to a server-side upload folder;
- recent-scan history is browser-tab-only, so one visitor cannot read filenames from another visitor's scans.

## Deployment

The repository includes a Dockerfile for a small public demo deployment. The container installs the native ZBar runtime and starts FastAPI on the platform-provided `PORT`. QuishLens is still a hackathon prototype: public deployments should keep file-size/page limits in place and should not be described as a production malware gateway.

After deployment, check `/api/health` or the Runtime panel before recording a demo. At least one QR decoder must be available; ideally ZXing-C++, ZBar, and OpenCV all report ready.

## AI/tool disclosure

The project uses machine-learning components for phishing/anomaly classification and may be developed with AI-assisted coding/debugging tools. The actual runtime architecture does not depend on an LLM making the final safety decision. Significant AI/tool assistance should be disclosed wherever the competition rules require it.

---

**Read the square. Understand the square. Then decide whether the square deserves your trust.**

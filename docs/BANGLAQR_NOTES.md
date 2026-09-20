# BanglaQR-Quish notes

The provided release contains 50,000 synthetic payment QR images: 25,000 benign and 25,000 malicious.

Malicious samples are split between:

- `provider_gui_url_injection`
- `payment_redirection`

QuishLens treats those two attacks differently.

Provider URL injection has a semantic signal available in a single QR: the provider-identifier field itself contains a URL. That can be detected deterministically.

Payment redirection is harder. A QR can remain correctly formatted, pass its CRC, and still contain a changed receiver/account. Without a known-good reference, provider validation service, surrounding context, or a trained anomaly model, syntax alone cannot prove that receiver is wrong.

That distinction is intentionally retained in the project so the benchmark does not turn into a collection of dataset-specific `if value.startswith("9999")` tricks.

The optional Random Forest payment model is trained only on generic structural/content-shape features and is marked research-only.

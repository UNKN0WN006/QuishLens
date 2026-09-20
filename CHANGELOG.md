# Changelog

## 1.3.0

- Rebuilt the interface around a centred top identity and horizontal navigation.
- Added a lightweight opening QR -> payload -> explanation animation.
- Made Simple view materially different from Detailed view.
- Added QR payload classification for URLs, EMV payments, UPI, Wi-Fi, contacts, SMS, phone, location, OTP secrets and text.
- Added EMV TLV parsing and CRC validation.
- Added payment-provider URL injection detection.
- Added an optional BanglaQR-Quish payment anomaly model and training script.
- Added direct BanglaQR-Quish ZIP evaluation without extracting 50,000 files.
- Added QR-only ZBar fallback while deliberately ignoring one-dimensional barcodes.
- Added safe embedded redirect-parameter extraction without following the network.
- Added 5 payload-analysis tests; 11 automated tests now pass.

## 1.1.0

- Improved PDF fast path and batch URL benchmark inference.
- Introduced the warmer safety/forensic visual direction.

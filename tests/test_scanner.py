from pathlib import Path

import qrcode

from app.scanner.qr_detector import decode_qr_from_bytes


def test_qr_decode_round_trip(tmp_path: Path):
    expected = "https://example.invalid/test"
    path = tmp_path / "qr.png"
    qrcode.make(expected).save(path)
    decoded = decode_qr_from_bytes(path.read_bytes())
    assert any(item.payload == expected for item in decoded)

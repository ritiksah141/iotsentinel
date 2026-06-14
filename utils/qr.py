"""Tiny helper: generate a QR code as a data-URI PNG.

Uses the qrcode[pil] library (already a declared dependency — also used by
utils/totp_manager.py for 2FA setup).
"""

import base64
import io

import qrcode
import qrcode.constants


def make_qr_data_uri(text: str, box_size: int = 6, border: int = 2) -> str:
    """Return a base64-encoded data-URI for a QR code of *text*.

    Args:
        text: The string to encode.
        box_size: Pixels per QR module (default 6 — compact for wizard UI).
        border: Quiet-zone width in modules (default 2 — compact).

    Returns:
        ``data:image/png;base64,<...>`` string suitable for an <img src>.
    """
    qr = qrcode.QRCode(
        version=None,  # auto-fit
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(text)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

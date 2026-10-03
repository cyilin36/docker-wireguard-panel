"""QR codes for client configurations.

segno is pure Python (no compiled dependencies), which keeps the image small.
Codes are rendered dark-on-light so any phone camera can read them.
"""

from __future__ import annotations

import io

import segno

DARK = "#0b0f14"
LIGHT = "#ffffff"


def svg(data: str, *, scale: int = 4, border: int = 2) -> str:
    qr = segno.make(data, error="m")
    # segno's SVG writer emits bytes; decode explicitly so the result can be
    # handed straight to the HTTP layer as text.
    buffer = io.BytesIO()
    qr.save(
        buffer,
        kind="svg",
        scale=scale,
        border=border,
        dark=DARK,
        light=LIGHT,
        xmldecl=False,
        svgns=True,
        nl=False,
    )
    return buffer.getvalue().decode("utf-8")


def png(data: str, *, scale: int = 6, border: int = 2) -> bytes:
    qr = segno.make(data, error="m")
    buffer = io.BytesIO()
    qr.save(buffer, kind="png", scale=scale, border=border, dark=DARK, light=LIGHT)
    return buffer.getvalue()

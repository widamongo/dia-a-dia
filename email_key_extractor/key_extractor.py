"""
Extractor de claves desde cuerpos de correo electrónico.

Estrategia:
  1. Cada patrón tiene: nombre del sistema, expresión regular y nivel de confianza.
  2. Si se detecta más de un patrón en el mismo mensaje se devuelven todos.
  3. Los resultados de baja confianza se marcan para revisión manual antes de
     persistirse en el vault.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ExtractedKey:
    system: str          # Nombre del sistema al que pertenece la clave
    key_type: str        # "password" | "otp" | "token" | "confirmation_code"
    value: str           # Valor de la clave (se cifra antes de persistir)
    confidence: Confidence
    raw_match: str       # Fragmento original del correo donde se encontró
    needs_review: bool = field(init=False)

    def __post_init__(self) -> None:
        self.needs_review = self.confidence != Confidence.HIGH

    def masked(self) -> str:
        """Devuelve la clave parcialmente oculta para logs de auditoría."""
        if len(self.value) <= 4:
            return "****"
        return self.value[:2] + "*" * (len(self.value) - 4) + self.value[-2:]


# ──────────────────────────────────────────────────────────────────────────────
# Patrones de detección
# Ajusta o amplía esta lista según los formatos reales de tus correos.
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class _Pattern:
    system: str
    key_type: str
    regex: re.Pattern[str]
    confidence: Confidence


_PATTERNS: list[_Pattern] = [
    # ── Contraseñas Oracle explícitas ──────────────────────────────────────────
    _Pattern(
        system="Oracle-OPS",
        key_type="password",
        regex=re.compile(
            r"(?:clave|contrase[ñn]a|password)[:\s]+([A-Za-z0-9@#$%!_\-\.]{6,30})",
            re.IGNORECASE,
        ),
        confidence=Confidence.HIGH,
    ),
    # ── OTP / código de verificación (6-8 dígitos) ─────────────────────────────
    _Pattern(
        system="OTP",
        key_type="otp",
        regex=re.compile(
            r"(?:c[oó]digo|token|otp|verification\s+code)[:\s]+(\d{6,8})",
            re.IGNORECASE,
        ),
        confidence=Confidence.HIGH,
    ),
    # ── Patrón heurístico: cadena alfanumérica de 8-16 chars entre comillas ─────
    _Pattern(
        system="UNKNOWN",
        key_type="password",
        regex=re.compile(
            r'["\'`]([A-Za-z0-9@#$%!_\-]{8,16})[\"\'`]',
        ),
        confidence=Confidence.MEDIUM,
    ),
    # ── Token tipo ****** API key ────────────────────────────────────────────
    _Pattern(
        system="API",
        key_type="token",
        regex=re.compile(
            r"(?:bearer|api[_\s]?key|access[_\s]?token)[:\s]+([A-Za-z0-9\-_\.]{20,})",
            re.IGNORECASE,
        ),
        confidence=Confidence.HIGH,
    ),
    # ── Código de confirmación genérico de 4-10 dígitos ───────────────────────
    _Pattern(
        system="CONFIRMATION",
        key_type="confirmation_code",
        regex=re.compile(
            r"(?:confirma|confirmation|c[oó]digo\s+de\s+acceso)[:\s]+(\d{4,10})",
            re.IGNORECASE,
        ),
        confidence=Confidence.MEDIUM,
    ),
]

# Remitentes/asuntos de plena confianza: elevan MEDIUM → HIGH automáticamente
_TRUSTED_SENDERS: set[str] = set()          # Agrega dominios o correos completos
_TRUSTED_SUBJECT_KEYWORDS: list[str] = []   # Palabras clave en asunto de confianza


def _elevate_confidence(
    conf: Confidence, sender: str, subject: str
) -> Confidence:
    """Eleva la confianza si el remitente/asunto coincide con fuentes confiables."""
    if conf == Confidence.HIGH:
        return conf
    sender_trusted = any(t in sender.lower() for t in _TRUSTED_SENDERS)
    subject_trusted = any(k.lower() in subject.lower() for k in _TRUSTED_SUBJECT_KEYWORDS)
    if sender_trusted or subject_trusted:
        return Confidence.HIGH
    return conf


def extract_keys(
    body: str,
    sender: str = "",
    subject: str = "",
) -> list[ExtractedKey]:
    """
    Extrae todas las claves detectables en el cuerpo del mensaje.

    Args:
        body:    Cuerpo del correo (texto plano, sin HTML).
        sender:  Dirección del remitente (opcional, mejora confianza).
        subject: Asunto del mensaje (opcional, mejora confianza).

    Returns:
        Lista de ExtractedKey. Puede estar vacía si no se detectó nada.
    """
    found: list[ExtractedKey] = []
    for pattern in _PATTERNS:
        for match in pattern.regex.finditer(body):
            value = match.group(1).strip()
            if not value:
                continue
            confidence = _elevate_confidence(pattern.confidence, sender, subject)
            found.append(
                ExtractedKey(
                    system=pattern.system,
                    key_type=pattern.key_type,
                    value=value,
                    confidence=confidence,
                    raw_match=match.group(0)[:120],  # Limita el fragmento guardado
                )
            )
    # Deduplica por (system, value)
    seen: set[tuple[str, str]] = set()
    unique: list[ExtractedKey] = []
    for k in found:
        key = (k.system, k.value)
        if key not in seen:
            seen.add(key)
            unique.append(k)
    return unique

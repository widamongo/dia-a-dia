"""
Registro de evidencias (audit log) en formato JSONL.

Cada línea es un objeto JSON con:
  - timestamp     : ISO 8601 UTC
  - event         : tipo de evento
  - message_id    : ID del correo procesado
  - subject       : asunto del correo
  - sender        : remitente
  - system        : sistema al que pertenece la clave
  - key_type      : tipo de clave
  - masked_value  : valor parcialmente oculto (nunca el valor completo)
  - confidence    : nivel de confianza de la extracción
  - needs_review  : si requiere revisión manual
  - vault_name    : nombre/ID del secreto en el vault
  - status        : "stored" | "skipped" | "review_required" | "error"
  - detail        : información adicional (errores, motivos)

El log nunca almacena claves en claro.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config

logger = logging.getLogger(__name__)


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or config.AUDIT_LOG_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _write(self, record: dict[str, Any]) -> None:
        record["timestamp"] = datetime.now(timezone.utc).isoformat()
        line = json.dumps(record, ensure_ascii=False)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        logger.debug("Audit event: %s status=%s", record.get("event"), record.get("status"))

    def log_stored(
        self,
        *,
        message_id: str,
        subject: str,
        sender: str,
        system: str,
        key_type: str,
        masked_value: str,
        confidence: str,
        needs_review: bool,
        vault_name: str,
    ) -> None:
        self._write({
            "event": "KEY_STORED",
            "message_id": message_id,
            "subject": subject,
            "sender": sender,
            "system": system,
            "key_type": key_type,
            "masked_value": masked_value,
            "confidence": confidence,
            "needs_review": needs_review,
            "vault_name": vault_name,
            "status": "stored",
            "detail": "",
        })

    def log_review_required(
        self,
        *,
        message_id: str,
        subject: str,
        sender: str,
        system: str,
        key_type: str,
        masked_value: str,
        confidence: str,
        reason: str,
    ) -> None:
        self._write({
            "event": "REVIEW_REQUIRED",
            "message_id": message_id,
            "subject": subject,
            "sender": sender,
            "system": system,
            "key_type": key_type,
            "masked_value": masked_value,
            "confidence": confidence,
            "needs_review": True,
            "vault_name": "",
            "status": "review_required",
            "detail": reason,
        })

    def log_skipped(
        self,
        *,
        message_id: str,
        subject: str,
        sender: str,
        reason: str,
    ) -> None:
        self._write({
            "event": "MESSAGE_SKIPPED",
            "message_id": message_id,
            "subject": subject,
            "sender": sender,
            "system": "",
            "key_type": "",
            "masked_value": "",
            "confidence": "",
            "needs_review": False,
            "vault_name": "",
            "status": "skipped",
            "detail": reason,
        })

    def log_error(
        self,
        *,
        message_id: str,
        subject: str,
        sender: str,
        error: str,
    ) -> None:
        self._write({
            "event": "ERROR",
            "message_id": message_id,
            "subject": subject,
            "sender": sender,
            "system": "",
            "key_type": "",
            "masked_value": "",
            "confidence": "",
            "needs_review": True,
            "vault_name": "",
            "status": "error",
            "detail": error,
        })

    def log_run_summary(self, *, stored: int, review: int, skipped: int, errors: int) -> None:
        self._write({
            "event": "RUN_SUMMARY",
            "message_id": "",
            "subject": "",
            "sender": "",
            "system": "",
            "key_type": "",
            "masked_value": "",
            "confidence": "",
            "needs_review": False,
            "vault_name": "",
            "status": "summary",
            "detail": f"stored={stored} review_required={review} skipped={skipped} errors={errors}",
        })

"""
Orquestador principal del extractor de claves desde correo.

Flujo:
  1. Leer mensajes de la carpeta configurada (EMAIL_FOLDER_NAME).
  2. Para cada mensaje, extraer claves detectadas.
  3. Claves de confianza HIGH → almacenar en vault + registrar evidencia.
     Claves de confianza MEDIUM/LOW → registrar como "review_required" (no se guardan automáticamente).
  4. Marcar el mensaje como leído (procesado) en Outlook.
  5. Generar resumen al finalizar.

Ejecutar:
    python -m email_key_extractor.main

O desde la raíz del proyecto:
    python -m email_key_extractor
"""

from __future__ import annotations

import logging
import sys

from . import config
from .audit_log import AuditLog
from .email_reader import fetch_messages, mark_as_processed
from .key_extractor import Confidence, extract_keys
from .vault import get_vault

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


def run() -> None:
    audit = AuditLog()
    vault = get_vault()

    counters = {"stored": 0, "review": 0, "skipped": 0, "errors": 0}

    logger.info("=== Inicio del extractor de claves ===")

    try:
        messages = fetch_messages()
    except Exception as exc:
        logger.error("Error al conectar con el correo: %s", exc)
        sys.exit(1)

    for msg in messages:
        logger.info("Procesando: [%s] %s", msg.received_at[:10], msg.subject or "(sin asunto)")
        try:
            keys = extract_keys(msg.body_text, sender=msg.sender, subject=msg.subject)

            if not keys:
                audit.log_skipped(
                    message_id=msg.message_id,
                    subject=msg.subject,
                    sender=msg.sender,
                    reason="No se detectaron claves",
                )
                counters["skipped"] += 1
                mark_as_processed(msg.message_id)
                continue

            for key in keys:
                if key.confidence == Confidence.HIGH:
                    vault_name = vault.store(
                        system=key.system,
                        key_type=key.key_type,
                        value=key.value,
                        ttl_days=config.KEY_TTL_DAYS,
                    )
                    audit.log_stored(
                        message_id=msg.message_id,
                        subject=msg.subject,
                        sender=msg.sender,
                        system=key.system,
                        key_type=key.key_type,
                        masked_value=key.masked(),
                        confidence=key.confidence.value,
                        needs_review=key.needs_review,
                        vault_name=vault_name,
                    )
                    counters["stored"] += 1
                else:
                    # Baja/media confianza → no se guarda automáticamente
                    audit.log_review_required(
                        message_id=msg.message_id,
                        subject=msg.subject,
                        sender=msg.sender,
                        system=key.system,
                        key_type=key.key_type,
                        masked_value=key.masked(),
                        confidence=key.confidence.value,
                        reason=f"Confianza {key.confidence.value}: requiere validación manual",
                    )
                    counters["review"] += 1
                    logger.warning(
                        "⚠️  Clave de baja confianza detectada en mensaje '%s' – revisa %s",
                        msg.subject,
                        config.AUDIT_LOG_PATH,
                    )

            mark_as_processed(msg.message_id)

        except Exception as exc:
            logger.error("Error procesando mensaje '%s': %s", msg.subject, exc)
            audit.log_error(
                message_id=msg.message_id,
                subject=msg.subject,
                sender=msg.sender,
                error=str(exc),
            )
            counters["errors"] += 1

    audit.log_run_summary(**counters)
    logger.info(
        "=== Resumen: almacenadas=%d  revisión_requerida=%d  sin_claves=%d  errores=%d ===",
        counters["stored"],
        counters["review"],
        counters["skipped"],
        counters["errors"],
    )


if __name__ == "__main__":
    run()

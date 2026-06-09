"""
Lector de correos usando Microsoft Graph API.
Solo lee la carpeta configurada (EMAIL_FOLDER_NAME) para minimizar exposición.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Generator

import requests
from msal import ConfidentialClientApplication

from . import config

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_SCOPES = ["https://graph.microsoft.com/.default"]


@dataclass
class EmailMessage:
    message_id: str
    subject: str
    sender: str
    received_at: str
    body_text: str
    folder_id: str


def _get_access_token() -> str:
    """Obtiene token OAuth2 usando credenciales de aplicación (client credentials flow)."""
    app = ConfidentialClientApplication(
        client_id=config.GRAPH_CLIENT_ID,
        client_credential=config.GRAPH_CLIENT_SECRET,
        authority=f"https://login.microsoftonline.com/{config.GRAPH_TENANT_ID}",
    )
    result = app.acquire_token_for_client(scopes=_SCOPES)
    if "access_token" not in result:
        raise RuntimeError(
            f"No se pudo obtener token de acceso: {result.get('error_description')}"
        )
    return result["access_token"]


def _get_folder_id(token: str, folder_name: str) -> str:
    """Busca el ID de la carpeta de correo por nombre."""
    url = f"{_GRAPH_BASE}/users/{config.GRAPH_USER_EMAIL}/mailFolders"
    headers = {"Authorization": "Bearer " + token}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    folders = resp.json().get("value", [])
    for folder in folders:
        if folder["displayName"].lower() == folder_name.lower():
            return folder["id"]
    raise ValueError(
        f"Carpeta '{folder_name}' no encontrada. "
        "Créala en Outlook y define una regla para mover los correos con claves."
    )


def _iter_messages(
    token: str, folder_id: str, max_messages: int
) -> Generator[dict, None, None]:
    """Itera los mensajes de la carpeta usando paginación."""
    url = (
        f"{_GRAPH_BASE}/users/{config.GRAPH_USER_EMAIL}"
        f"/mailFolders/{folder_id}/messages"
        f"?$top=20&$select=id,subject,from,receivedDateTime,body&$orderby=receivedDateTime desc"
    )
    headers = {"Authorization": "Bearer " + token}
    fetched = 0
    while url and fetched < max_messages:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        for msg in data.get("value", []):
            if fetched >= max_messages:
                return
            yield msg
            fetched += 1
        url = data.get("@odata.nextLink")


def fetch_messages() -> list[EmailMessage]:
    """
    Conecta a Outlook, accede a la carpeta configurada y devuelve los mensajes
    listos para análisis. No descarga adjuntos.
    """
    token = _get_access_token()
    folder_id = _get_folder_id(token, config.EMAIL_FOLDER_NAME)
    logger.info("Leyendo carpeta '%s' (max %d mensajes)", config.EMAIL_FOLDER_NAME, config.EMAIL_MAX_MESSAGES)

    messages: list[EmailMessage] = []
    for raw in _iter_messages(token, folder_id, config.EMAIL_MAX_MESSAGES):
        body = raw.get("body", {})
        # Prefiere texto plano; si solo hay HTML, usa el contenido HTML (el extractor lo limpia)
        body_text: str = body.get("content", "") if body.get("contentType") == "text" else _strip_html(body.get("content", ""))
        messages.append(
            EmailMessage(
                message_id=raw["id"],
                subject=raw.get("subject", ""),
                sender=raw.get("from", {}).get("emailAddress", {}).get("address", ""),
                received_at=raw.get("receivedDateTime", ""),
                body_text=body_text,
                folder_id=folder_id,
            )
        )

    logger.info("Mensajes cargados: %d", len(messages))
    return messages


def mark_as_processed(message_id: str) -> None:
    """
    Mueve el mensaje procesado a la carpeta 'Elementos procesados' o lo marca
    con una categoría. Aquí simplemente lo marcamos como leído.
    """
    token = _get_access_token()
    url = f"{_GRAPH_BASE}/users/{config.GRAPH_USER_EMAIL}/messages/{message_id}"
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    }
    requests.patch(url, headers=headers, json={"isRead": True}, timeout=30).raise_for_status()


def _strip_html(html: str) -> str:
    """Eliminación básica de etiquetas HTML sin dependencias extra."""
    import re
    clean = re.sub(r"<[^>]+>", " ", html)
    return " ".join(clean.split())

"""
Configuración centralizada del extractor de claves desde correo.
Todas las variables sensibles se cargan desde variables de entorno o archivo .env
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar .env desde la raíz del proyecto o desde esta carpeta
_env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=_env_path)

# ── Microsoft Graph / Outlook ──────────────────────────────────────────────────
GRAPH_TENANT_ID: str = os.environ["GRAPH_TENANT_ID"]
GRAPH_CLIENT_ID: str = os.environ["GRAPH_CLIENT_ID"]
GRAPH_CLIENT_SECRET: str = os.environ["GRAPH_CLIENT_SECRET"]
GRAPH_USER_EMAIL: str = os.environ["GRAPH_USER_EMAIL"]

# Nombre exacto de la carpeta de correo que contiene los mensajes con claves.
# Créala manualmente en Outlook y define una regla de bandeja para mover ahí
# los correos con claves antes de ejecutar este script.
EMAIL_FOLDER_NAME: str = os.getenv("EMAIL_FOLDER_NAME", "Claves-Automatizacion")

# Máximo de correos a procesar por ejecución (evita sobrecarga en primer uso)
EMAIL_MAX_MESSAGES: int = int(os.getenv("EMAIL_MAX_MESSAGES", "50"))

# ── Vault local cifrado ────────────────────────────────────────────────────────
# Contraseña maestra para el vault local (Fernet).
# Si usas Azure Key Vault, esta variable no es necesaria.
LOCAL_VAULT_PASSWORD: str = os.getenv("LOCAL_VAULT_PASSWORD", "")
LOCAL_VAULT_PATH: Path = Path(os.getenv("LOCAL_VAULT_PATH", "vault.enc"))

# ── Azure Key Vault (opcional) ─────────────────────────────────────────────────
AZURE_VAULT_URL: str = os.getenv("AZURE_VAULT_URL", "")

# ── Registro de evidencias ────────────────────────────────────────────────────
AUDIT_LOG_PATH: Path = Path(os.getenv("AUDIT_LOG_PATH", "audit.log"))

# Tiempo máximo de vigencia de una clave en el vault (en días).
# Pasado este tiempo la clave se marca como expirada en el log.
KEY_TTL_DAYS: int = int(os.getenv("KEY_TTL_DAYS", "1"))

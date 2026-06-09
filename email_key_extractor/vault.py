"""
Capa de almacenamiento seguro de claves (vault).

Soporta dos backends:
  - LocalVault  : archivo cifrado con Fernet (AES-128-CTR + HMAC-SHA256).
                  Derivación de clave con PBKDF2-HMAC-SHA256.
                  Adecuado para entornos sin acceso a cloud vault.
  - AzureVault  : Azure Key Vault via azure-keyvault-secrets.
                  Recomendado para entornos corporativos.

Uso:
    from email_key_extractor.vault import get_vault
    vault = get_vault()
    vault.store("Oracle-OPS", "password", "mi_clave_cifrada", ttl_days=1)
    entry = vault.retrieve("Oracle-OPS", "password")
"""

from __future__ import annotations

import base64
import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import config

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Interfaz base
# ──────────────────────────────────────────────────────────────────────────────

class VaultBase(ABC):
    @abstractmethod
    def store(self, system: str, key_type: str, value: str, ttl_days: int = 1) -> str:
        """Almacena una clave y devuelve su nombre/ID en el vault."""

    @abstractmethod
    def retrieve(self, system: str, key_type: str) -> str | None:
        """Recupera el valor más reciente. Devuelve None si no existe o expiró."""

    @abstractmethod
    def list_entries(self) -> list[dict]:
        """Lista metadatos de todas las entradas (sin valores en claro)."""


# ──────────────────────────────────────────────────────────────────────────────
# Vault local cifrado
# ──────────────────────────────────────────────────────────────────────────────

_SALT_SIZE = 16
_KDF_ITERATIONS = 390_000  # Recomendación OWASP 2023


def _derive_fernet_key(password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)


class LocalVault(VaultBase):
    """
    Almacena las entradas como JSON cifrado en un único archivo.
    Estructura del JSON:
        {
          "salt": "<base64>",
          "entries": [
            {
              "system": "Oracle-OPS",
              "key_type": "password",
              "ciphertext": "<base64 Fernet token>",
              "stored_at": "<ISO datetime>",
              "expires_at": "<ISO datetime>"
            },
            ...
          ]
        }
    """

    def __init__(self, path: Path, password: str) -> None:
        if not password:
            raise ValueError(
                "LOCAL_VAULT_PASSWORD no puede estar vacío. "
                "Define la variable de entorno antes de ejecutar."
            )
        self._path = path
        self._password = password
        self._data: dict = self._load()

    # ── Persistencia ──────────────────────────────────────────────────────────

    def _load(self) -> dict:
        if not self._path.exists():
            salt = os.urandom(_SALT_SIZE)
            return {"salt": base64.b64encode(salt).decode(), "entries": []}
        raw = self._path.read_bytes()
        # El archivo comienza con el salt (16 bytes) seguido del token Fernet
        salt = raw[:_SALT_SIZE]
        fernet = _derive_fernet_key(self._password, salt)
        plaintext = fernet.decrypt(raw[_SALT_SIZE:])
        return json.loads(plaintext)

    def _save(self) -> None:
        salt = base64.b64decode(self._data["salt"])
        fernet = _derive_fernet_key(self._password, salt)
        plaintext = json.dumps(self._data, ensure_ascii=False).encode()
        ciphertext = fernet.encrypt(plaintext)
        self._path.write_bytes(salt + ciphertext)
        logger.debug("Vault guardado en %s", self._path)

    # ── Operaciones ───────────────────────────────────────────────────────────

    def store(self, system: str, key_type: str, value: str, ttl_days: int = 1) -> str:
        salt = base64.b64decode(self._data["salt"])
        fernet = _derive_fernet_key(self._password, salt)
        ciphertext = fernet.encrypt(value.encode()).decode()
        now = datetime.now(timezone.utc)
        entry = {
            "system": system,
            "key_type": key_type,
            "ciphertext": ciphertext,
            "stored_at": now.isoformat(),
            "expires_at": (now + timedelta(days=ttl_days)).isoformat(),
        }
        self._data["entries"].append(entry)
        self._save()
        vault_entry_name = f"{system}/{key_type}"
        logger.info("Clave almacenada en vault local: %s (expira en %d día/s)", vault_entry_name, ttl_days)
        return vault_entry_name

    def retrieve(self, system: str, key_type: str) -> str | None:
        salt = base64.b64decode(self._data["salt"])
        fernet = _derive_fernet_key(self._password, salt)
        now = datetime.now(timezone.utc)
        # Devuelve la más reciente que no haya expirado
        candidates = [
            e for e in self._data["entries"]
            if e["system"] == system
            and e["key_type"] == key_type
            and datetime.fromisoformat(e["expires_at"]) > now
        ]
        if not candidates:
            return None
        latest = max(candidates, key=lambda e: e["stored_at"])
        return fernet.decrypt(latest["ciphertext"].encode()).decode()

    def list_entries(self) -> list[dict]:
        now = datetime.now(timezone.utc)
        return [
            {
                "system": e["system"],
                "key_type": e["key_type"],
                "stored_at": e["stored_at"],
                "expires_at": e["expires_at"],
                "expired": datetime.fromisoformat(e["expires_at"]) <= now,
            }
            for e in self._data["entries"]
        ]


# ──────────────────────────────────────────────────────────────────────────────
# Azure Key Vault (opcional)
# ──────────────────────────────────────────────────────────────────────────────

class AzureVault(VaultBase):
    """
    Wrapper sobre azure-keyvault-secrets.
    Requiere que la identidad del proceso tenga permiso 'Secret Officer' o
    'Secret User' en el Key Vault de Azure.
    """

    def __init__(self, vault_url: str) -> None:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        credential = DefaultAzureCredential()
        self._client = SecretClient(vault_url=vault_url, credential=credential)
        logger.info("Conectado a Azure Key Vault: %s", vault_url)

    @staticmethod
    def _secret_name(system: str, key_type: str) -> str:
        # Azure Key Vault solo admite letras, dígitos y guiones en nombres
        return f"{system}-{key_type}".replace("_", "-").replace("/", "-")

    def store(self, system: str, key_type: str, value: str, ttl_days: int = 1) -> str:
        name = self._secret_name(system, key_type)
        expires = datetime.now(timezone.utc) + timedelta(days=ttl_days)
        self._client.set_secret(name, value, expires_on=expires)
        logger.info("Clave almacenada en Azure Key Vault: %s", name)
        return name

    def retrieve(self, system: str, key_type: str) -> str | None:
        from azure.core.exceptions import ResourceNotFoundError
        name = self._secret_name(system, key_type)
        try:
            secret = self._client.get_secret(name)
            return secret.value
        except ResourceNotFoundError:
            return None

    def list_entries(self) -> list[dict]:
        return [
            {"name": p.name, "enabled": p.enabled, "expires_on": str(p.expires_on)}
            for p in self._client.list_properties_of_secrets()
        ]


# ──────────────────────────────────────────────────────────────────────────────
# Factoría
# ──────────────────────────────────────────────────────────────────────────────

def get_vault() -> VaultBase:
    """
    Devuelve el vault configurado según las variables de entorno:
      - Si AZURE_VAULT_URL está definida → AzureVault
      - En caso contrario              → LocalVault
    """
    if config.AZURE_VAULT_URL:
        return AzureVault(config.AZURE_VAULT_URL)
    return LocalVault(config.LOCAL_VAULT_PATH, config.LOCAL_VAULT_PASSWORD)

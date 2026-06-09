# Email Key Extractor – MVP

Automatiza la primera tarea del monitoreo diario:  
**leer bandeja filtrada → detectar clave → guardar en vault cifrado → registrar evidencia**.

---

## Requisitos previos

| Elemento | Descripción |
|----------|-------------|
| Python ≥ 3.11 | Entorno de ejecución |
| Cuenta Outlook / Office 365 | Buzón del cual se leerán las claves |
| Azure App Registration | Para autenticar con Microsoft Graph (ver paso 1) |
| (Opcional) Azure Key Vault | Para almacenamiento corporativo de secretos |

---

## Configuración en 5 pasos

### 1. Registrar la aplicación en Azure

1. Ir a [Azure Portal → App Registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade).
2. Crear nueva aplicación → copiar **Tenant ID**, **Client ID**.
3. Certificados y secretos → Nuevo secreto de cliente → copiar el valor (**Client Secret**).
4. Permisos de API → Agregar permiso → Microsoft Graph → **Permisos de aplicación**:
   - `Mail.Read`
   - `Mail.ReadWrite` (para marcar como leídos)
5. Conceder consentimiento de administrador.

### 2. Crear carpeta y regla en Outlook

1. Crear carpeta **"Claves-Automatizacion"** en tu bandeja.
2. Crear una regla que mueva automáticamente a esa carpeta los correos que contengan claves (por remitente, asunto, etc.).

### 3. Instalar dependencias

```bash
cd email_key_extractor
pip install -r requirements.txt
```

Para usar Azure Key Vault, descomenta también:
```bash
pip install azure-identity azure-keyvault-secrets
```

### 4. Configurar variables de entorno

```bash
cp .env.example .env
# Edita .env con tus valores reales
```

> ⚠️ **Nunca subas `.env` al repositorio.** Está en `.gitignore`.

### 5. Ejecutar

```bash
# Desde la raíz del proyecto
python -m email_key_extractor.main
```

---

## Estructura del módulo

```
email_key_extractor/
├── __init__.py        # Punto de entrada del paquete
├── config.py          # Configuración centralizada desde variables de entorno
├── email_reader.py    # Lector Microsoft Graph API
├── key_extractor.py   # Extracción de claves por patrones (regex)
├── vault.py           # Vault local cifrado (Fernet) y Azure Key Vault
├── audit_log.py       # Registro de evidencias en JSONL (sin claves en claro)
├── main.py            # Orquestador principal
├── requirements.txt
├── .env.example
└── README.md
```

---

## Flujo de procesamiento

```
Outlook (carpeta filtrada)
        │
        ▼
  email_reader.py  ──→  Mensajes sin procesar
        │
        ▼
  key_extractor.py ──→  Claves detectadas + nivel de confianza
        │
        ├─ Confianza HIGH ──→  vault.py (cifrado) ──→ audit_log.py (evidencia)
        │
        └─ Confianza MEDIUM/LOW ──→ audit_log.py (marcado para revisión manual)
```

---

## Agregar nuevos patrones de detección

Edita `key_extractor.py`, sección `_PATTERNS`:

```python
_Pattern(
    system="MiSistema",
    key_type="password",
    regex=re.compile(r"Tu patrón regex aquí: ([A-Za-z0-9]{8,20})", re.IGNORECASE),
    confidence=Confidence.HIGH,
),
```

---

## Seguridad

- Las claves **nunca** se escriben en texto plano en ningún archivo.
- El vault local usa **AES-128-CTR + HMAC-SHA256** (Fernet) con derivación de clave PBKDF2 (390 000 iteraciones).
- El log de auditoría solo guarda el valor **enmascarado** (`ab****xy`).
- Las claves expiran automáticamente según `KEY_TTL_DAYS`.
- Para entornos corporativos, usar **Azure Key Vault** en lugar del vault local.

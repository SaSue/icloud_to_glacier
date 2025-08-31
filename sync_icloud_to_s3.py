
#!/usr/bin/env python3
# Incrementelle iCloud‑Fotosicherung nach AWS S3 (Glacier‑* Storage Classes)
# Läuft headless im Docker‑Container (auch auf Raspberry Pi).
# - Liest iCloud Photos über pyicloud-ipd (mit 2FA-Unterstützung)
# - Lädt jedes Asset nacheinander lokal in eine Temp-Datei
# - Lädt die Datei direkt nach S3 hoch (z. B. DEEP_ARCHIVE oder GLACIER_IR)
# - Löscht die Temp-Datei wieder (konstanter Plattenbedarf)
# - Protokolliert erfolgreich hochgeladene Asset-IDs in einer SQLite‑DB
# - Bei erneutem Start werden nur neue/fehlende Assets übertragen
#
# Erforderliche ENV-Variablen (siehe README / .env.example):
#   APPLE_ID, APPLE_PASSWORD, S3_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
#
# Optional:
#   S3_PREFIX, S3_STORAGE_CLASS (Default: DEEP_ARCHIVE), AWS_DEFAULT_REGION,
#   LOOP_INTERVAL_SECONDS (Default: 21600 = 6h), MAX_ASSETS_PER_RUN,
#   ICLOUD_COOKIE_DIR (Default: /cookies), STATE_DB_PATH (Default: /state/db.sqlite3),
#   ICLOUD_2FA_CODE (nur beim ersten Lauf notwendig), S3_SSE, S3_SSE_KMS_KEY_ID
#
# Hinweis 2FA: Beim ersten Start ist ein 2FA‑Code nötig. Setze ICLOUD_2FA_CODE=123456
# (einmalig) oder starte den Container interaktiv, gib den Code ein und vertraue die Session.
# Cookies werden im Volume ICLOUD_COOKIE_DIR persistiert.

import os
import sys
import time
import logging
import sqlite3
import tempfile
import hashlib
from datetime import datetime
from pathlib import Path

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

# Wichtig: Das Paket heißt "pyicloud-ipd" und wird so importiert:
from pyicloud_ipd import PyiCloudService

# ---------- Konfiguration aus ENV ----------
APPLE_ID = os.environ.get("APPLE_ID")
APPLE_PASSWORD = os.environ.get("APPLE_PASSWORD")
ICLOUD_COOKIE_DIR = os.environ.get("ICLOUD_COOKIE_DIR", "/cookies")
STATE_DB_PATH = os.environ.get("STATE_DB_PATH", "/state/db.sqlite3")

AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "eu-central-1")
S3_BUCKET = os.environ.get("S3_BUCKET")
S3_PREFIX = os.environ.get("S3_PREFIX", "icloud/photos")
S3_STORAGE_CLASS = os.environ.get("S3_STORAGE_CLASS", "DEEP_ARCHIVE")  # Alternativen: GLACIER, GLACIER_IR
S3_SSE = os.environ.get("S3_SSE")  # "AES256" oder "aws:kms"
S3_SSE_KMS_KEY_ID = os.environ.get("S3_SSE_KMS_KEY_ID")  # falls aws:kms

LOOP_INTERVAL_SECONDS = int(os.environ.get("LOOP_INTERVAL_SECONDS", "21600"))  # 6h
MAX_ASSETS_PER_RUN = int(os.environ.get("MAX_ASSETS_PER_RUN", "0"))  # 0 = unbegrenzt

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# ---------- Logging ----------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("icloud-glacier-backup")

# ---------- Hilfsfunktionen ----------
def init_db(db_path: str):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(\"\"\"
        CREATE TABLE IF NOT EXISTS uploads (
            asset_id TEXT PRIMARY KEY,
            s3_key   TEXT NOT NULL,
            size     INTEGER,
            md5_hex  TEXT,
            uploaded_at TEXT NOT NULL
        )
    \"\"\")
    conn.commit()
    return conn

def md5_of_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def connect_icloud() -> PyiCloudService:
    if not APPLE_ID or not APPLE_PASSWORD:
        log.error("APPLE_ID und APPLE_PASSWORD müssen gesetzt sein.")
        sys.exit(2)

    cookie_dir = Path(ICLOUD_COOKIE_DIR)
    cookie_dir.mkdir(parents=True, exist_ok=True)

    api = PyiCloudService(APPLE_ID, APPLE_PASSWORD, cookie_directory=str(cookie_dir))

    # 2FA/2SA Behandlung
    if getattr(api, "requires_2sa", False):
        # Älteres 2‑Stufen Verfahren
        log.warning("iCloud verlangt 2‑Stufen-Verifizierung (2SA). Bitte Code eingeben.")
        code = os.environ.get("ICLOUD_2FA_CODE")
        if not code:
            log.error("Setze ICLOUD_2FA_CODE=XXXXXX für den ersten Lauf und starte erneut.")
            sys.exit(3)
        if not api.validate_2fa_code(code):
            log.error("2SA-Code ungültig.")
            sys.exit(4)
        if not api.is_trusted_session:
            api.trust_session()

    if getattr(api, "requires_2fa", False):
        # Modernes 2‑Faktor‑Verfahren
        log.warning("iCloud verlangt 2‑Faktor-Authentifizierung (2FA).")
        code = os.environ.get("ICLOUD_2FA_CODE")
        if not code:
            log.error("Setze ICLOUD_2FA_CODE=XXXXXX für den ersten Lauf und starte erneut.")
            sys.exit(3)
        if not api.validate_2fa_code(code):
            log.error("2FA-Code ungültig.")
            sys.exit(4)
        if not api.is_trusted_session:
            api.trust_session()

    return api

def s3_client():
    # Boto3 mit solider Retry-Konfiguration
    return boto3.client(
        "s3",
        region_name=AWS_REGION,
        config=BotoConfig(
            retries={"max_attempts": 10, "mode": "standard"},
            connect_timeout=30, read_timeout=300
        ),
    )

def s3_object_exists(s3, bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
            return False
        raise

def upload_file_to_s3(s3, local_path: str, key: str):
    extra = {"StorageClass": S3_STORAGE_CLASS}
    if S3_SSE:
        extra["ServerSideEncryption"] = S3_SSE
        if S3_SSE == "aws:kms" and S3_SSE_KMS_KEY_ID:
            extra["SSEKMSKeyId"] = S3_SSE_KMS_KEY_ID

    s3.upload_file(local_path, S3_BUCKET, key, ExtraArgs=extra)

def mark_uploaded(conn, asset_id: str, key: str, size: int, md5_hex: str):
    conn.execute(
        "INSERT OR REPLACE INTO uploads (asset_id, s3_key, size, md5_hex, uploaded_at) VALUES (?,?,?,?,?)",
        (asset_id, key, size, md5_hex, datetime.utcnow().isoformat(timespec="seconds")),
    )
    conn.commit()

def already_uploaded(conn, asset_id: str) -> bool:
    cur = conn.execute("SELECT 1 FROM uploads WHERE asset_id=?", (asset_id,))
    row = cur.fetchone()
    return bool(row)

def build_s3_key(asset, filename: str) -> str:
    # Jahres/Monats-Pfad nach Aufnahmedatum, falls verfügbar
    dt = getattr(asset, "asset_date", None) or getattr(asset, "created", None)
    if dt is None:
        dt = datetime.utcnow()
    try:
        year = dt.year
        month = dt.month
    except Exception:
        try:
            from datetime import datetime as _dt
            dt2 = _dt.fromisoformat(str(dt))
            year, month = dt2.year, dt2.month
        except Exception:
            year, month = 1970, 1

    safe_prefix = S3_PREFIX.strip("/")
    asset_id = getattr(asset, "id", None) or getattr(asset, "guid", None) or "unknownid"
    return f"{safe_prefix}/{year:04d}/{month:02d}/{asset_id}_{filename}"

def process_once():
    api = connect_icloud()
    conn = init_db(STATE_DB_PATH)
    s3 = s3_client()

    photos = getattr(api.photos.albums, "get", None)
    iterator = None
    if callable(photos) and api.photos.albums.get("All Photos"):
        iterator = api.photos.albums["All Photos"]
    else:
        iterator = api.photos.all

    processed = 0
    skipped = 0
    uploaded = 0

    for asset in iterator:
        asset_id = getattr(asset, "id", None) or getattr(asset, "guid", None)
        filename = getattr(asset, "filename", None) or f"{asset_id or 'asset'}.bin"

        if not asset_id:
            log.warning("Überspringe Asset ohne ID (Datei: %s)", filename)
            skipped += 1
            continue

        if already_uploaded(conn, asset_id):
            skipped += 1
            continue

        key = build_s3_key(asset, filename)
        if s3_object_exists(s3, S3_BUCKET, key):
            log.info("Schon in S3 vorhanden, trage in DB ein: %s", key)
            mark_uploaded(conn, asset_id, key, size=0, md5_hex="")
            skipped += 1
            continue

        try:
            dl = asset.download()
            if hasattr(dl, "iter_content"):
                iterator = dl.iter_content(chunk_size=1024 * 1024)
            else:
                resp = getattr(dl, "response", None) or getattr(dl, "raw", None) or dl
                iterator = resp.iter_content(chunk_size=1024 * 1024)

            with tempfile.NamedTemporaryFile(prefix="icloud_", suffix="_asset", delete=False) as tmp:
                tmp_path = tmp.name
                for chunk in iterator:
                    if chunk:
                        tmp.write(chunk)

            size = os.path.getsize(tmp_path)
            md5_hex = md5_of_file(tmp_path)

            upload_file_to_s3(s3, tmp_path, key)
            mark_uploaded(conn, asset_id, key, size=size, md5_hex=md5_hex)
            uploaded += 1
            log.info("Hochgeladen: %s (%s bytes) -> s3://%s/%s", filename, size, S3_BUCKET, key)

        except ClientError as e:
            log.error("AWS S3 Fehler bei %s: %s", filename, e)
        except Exception as e:
            log.error("Fehler bei %s: %s", filename, e)
        finally:
            try:
                if "tmp_path" in locals() and os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

        processed += 1
        if MAX_ASSETS_PER_RUN and processed >= MAX_ASSETS_PER_RUN:
            log.info("MAX_ASSETS_PER_RUN erreicht (%s).", MAX_ASSETS_PER_RUN)
            break

    log.info("Durchlauf beendet. verarbeitet=%s, hochgeladen=%s, übersprungen=%s",
             processed, uploaded, skipped)

def main():
    while True:
        try:
            process_once()
        except Exception as e:
            log.exception("Unerwarteter Fehler im Durchlauf: %s", e)
        log.info("Warte %s Sekunden bis zum nächsten Durchlauf ...", LOOP_INTERVAL_SECONDS)
        time.sleep(LOOP_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()

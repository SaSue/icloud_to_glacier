#!/usr/bin/env python3
# Incrementelle iCloud-Fotosicherung nach AWS S3 (Glacier-* Storage Classes) mit pyicloud
# Läuft headless im Docker-Container (Raspberry Pi geeignet).

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

from pyicloud import PyiCloudService
from glob import glob

APPLE_ID = os.environ.get("APPLE_ID")
APPLE_PASSWORD = os.environ.get("APPLE_PASSWORD")
ICLOUD_COOKIE_DIR = os.environ.get("ICLOUD_COOKIE_DIR", "/cookies")
STATE_DB_PATH = os.environ.get("STATE_DB_PATH", "/state/db.sqlite3")

AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "eu-central-1")
S3_BUCKET = os.environ.get("S3_BUCKET")
S3_PREFIX = os.environ.get("S3_PREFIX", "icloud/photos").strip("/")
S3_STORAGE_CLASS = os.environ.get("S3_STORAGE_CLASS", "DEEP_ARCHIVE")
S3_SSE = os.environ.get("S3_SSE")
S3_SSE_KMS_KEY_ID = os.environ.get("S3_SSE_KMS_KEY_ID")

LOOP_INTERVAL_SECONDS = int(os.environ.get("LOOP_INTERVAL_SECONDS", "21600"))
MAX_ASSETS_PER_RUN = int(os.environ.get("MAX_ASSETS_PER_RUN", "0"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

ICLOUD_2FA_CODE = os.environ.get("ICLOUD_2FA_CODE")
ICLOUD_2SA_DEVICE_INDEX = os.environ.get("ICLOUD_2SA_DEVICE_INDEX")
ICLOUD_2SA_SEND_CODE = os.environ.get("ICLOUD_2SA_SEND_CODE", "1")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("icloud-glacier-backup")

def _log_cookie_dir(cookie_dir: Path):
    try:
        files = list(cookie_dir.glob("*"))
        if not files:
            log.warning("Cookie-Verzeichnis ist leer: %s (Session kann nicht wiederverwendet werden)", cookie_dir)
        else:
            names = ", ".join(f.name for f in files[:10])
            more = "" if len(files) <= 10 else f" (+{len(files)-10} weitere)"
            log.info("Cookie-Dateien in %s: %s%s", cookie_dir, names, more)
    except Exception as e:
        log.debug("Cookie-Verzeichnis konnte nicht gelistet werden: %s", e)

def _persist_session(api):
    # Versuche diverse pyicloud-internen Hooks aufzurufen, damit Cookies sicher auf Disk landen
    for attr in ("save_session", "_store_session", "persist_session"):
        fn = getattr(api, attr, None)
        if callable(fn):
            try:
                fn()
                log.info("Session über %s() persistiert.", attr)
                return
            except Exception as e:
                log.debug("Persist via %s() fehlgeschlagen: %s", attr, e)
    # Letzter Versuch: falls die Requests-Cookies ein save() besitzen (MozillaCookieJar o.ä.)
    try:
        cj = getattr(api, "session", None)
        cj = getattr(cj, "cookies", None)
        if hasattr(cj, "save"):
            cj.save()
            log.info("Session-Cookies via cookiejar.save() persistiert.")
    except Exception as e:
        log.debug("cookiejar.save() fehlgeschlagen: %s", e)


def init_db(db_path: str):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS uploads (
            asset_id TEXT PRIMARY KEY,
            s3_key   TEXT NOT NULL,
            size     INTEGER,
            md5_hex  TEXT,
            uploaded_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn

def md5_of_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def connect_icloud() -> PyiCloudService:
    if not APPLE_ID or not APPLE_PASSWORD:
        log.error("APPLE_ID und APPLE_PASSWORD müssen gesetzt sein.")
        sys.exit(2)

    cookie_dir = Path(ICLOUD_COOKIE_DIR)
    cookie_dir.mkdir(parents=True, exist_ok=True)

    api = PyiCloudService(APPLE_ID, APPLE_PASSWORD, cookie_directory=str(cookie_dir))

    # Neuer 2FA-Flow
    if bool(getattr(api, "requires_2fa", False)):
        log.warning("iCloud verlangt 2FA. Setze ICLOUD_2FA_CODE=XXXXXX und starte neu.")
        if not ICLOUD_2FA_CODE:
            raise SystemExit("ICLOUD_2FA_CODE fehlt für 2FA.")
        validate_2fa = getattr(api, "validate_2fa_code", None)
        if callable(validate_2fa):
            if not validate_2fa(ICLOUD_2FA_CODE):
                raise SystemExit("2FA-Code ungültig.")
        else:
            log.error("validate_2fa_code nicht verfügbar – versuche 2SA-Flow.")

    # Älterer 2SA-Flow
    if bool(getattr(api, "requires_2sa", False)):
        log.warning("iCloud verlangt 2-Schritt-Bestätigung (2SA).")
        devices = getattr(api, "trusted_devices", [])
        if not devices:
            raise SystemExit("Keine trusted_devices gefunden – prüfe Apple-ID auf einem Gerät.")
        try:
            idx = int(ICLOUD_2SA_DEVICE_INDEX) if ICLOUD_2SA_DEVICE_INDEX else 0
        except Exception:
            idx = 0
        device = devices[min(max(idx, 0), len(devices)-1)]
        if ICLOUD_2SA_SEND_CODE not in ("0", "false", "False"):
            if not api.send_verification_code(device):
                raise SystemExit("Senden des 2SA-Codes fehlgeschlagen.")
        code = ICLOUD_2FA_CODE or os.environ.get("ICLOUD_2SA_CODE")
        if not code:
            raise SystemExit("Setze ICLOUD_2FA_CODE=XXXXXX (oder ICLOUD_2SA_CODE) und starte neu.")
        if not api.validate_verification_code(device, code):
            raise SystemExit("2SA/Verification-Code ungültig.")

    is_trusted = getattr(api, "is_trusted_session", None)
    if callable(is_trusted) and not api.is_trusted_session():
        trust = getattr(api, "trust_session", None)
        if callable(trust):
            try:
                trust()
                log.info("Session als trusted markiert.")
            except Exception as e:
                log.warning("Konnte Session nicht als trusted markieren: %s", e)

    return api

def s3_client():
    return boto3.client(
        "s3",
        region_name=AWS_REGION,
        config=BotoConfig(retries={"max_attempts": 10, "mode": "standard"}, connect_timeout=30, read_timeout=300),
    )

def s3_object_exists(s3, bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("404", "NoSuchKey", "NotFound"):
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
    return bool(cur.fetchone())

def build_s3_key(asset, filename: str) -> str:
    dt = getattr(asset, "asset_date", None) or getattr(asset, "created", None) or datetime.utcnow()
    try:
        year, month = dt.year, dt.month
    except Exception:
        try:
            from datetime import datetime as _dt
            _dt2 = _dt.fromisoformat(str(dt))
            year, month = _dt2.year, _dt2.month
        except Exception:
            year, month = 1970, 1
    asset_id = getattr(asset, "id", None) or getattr(asset, "guid", None) or "unknownid"
    return f"{S3_PREFIX}/{year:04d}/{month:02d}/{asset_id}_{filename}"

def process_once():
    api = connect_icloud()
    conn = init_db(STATE_DB_PATH)
    s3 = s3_client()

    try:
        iterator = api.photos.albums.get("All Photos") or api.photos.all
    except Exception:
        iterator = api.photos.all

    processed = skipped = uploaded = 0

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
                stream = dl.iter_content(chunk_size=1024 * 1024)
            else:
                resp = getattr(dl, "response", None) or getattr(dl, "raw", None) or dl
                stream = resp.iter_content(chunk_size=1024 * 1024)

            with tempfile.NamedTemporaryFile(prefix="icloud_", suffix="_asset", delete=False) as tmp:
                tmp_path = tmp.name
                for chunk in stream:
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

    log.info("Durchlauf beendet. verarbeitet=%s, hochgeladen=%s, übersprungen=%s", processed, uploaded, skipped)

def main():
    while True:
        try:
            process_once()
        except SystemExit as e:
            log.error(str(e))
            time.sleep(120)
        except Exception as e:
            log.exception("Unerwarteter Fehler im Durchlauf: %s", e)
            time.sleep(300)
        else:
            log.info("Warte %s Sekunden bis zum nächsten Durchlauf ...", LOOP_INTERVAL_SECONDS)
            time.sleep(LOOP_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()

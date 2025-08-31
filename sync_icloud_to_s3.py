#!/usr/bin/env python3
# iCloud → S3 (Glacier-*) incremental backup with pyicloud, interactive 2FA/2SA,
# trusted-session short-circuit, and cookie persistence.

import os, sys, time, logging, sqlite3, tempfile, hashlib, getpass
from datetime import datetime
from pathlib import Path

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from pyicloud import PyiCloudService

# ---- ENV ----
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

# 2FA/2SA inputs
ICLOUD_2FA_CODE = os.environ.get("ICLOUD_2FA_CODE")
ICLOUD_2SA_DEVICE_INDEX = os.environ.get("ICLOUD_2SA_DEVICE_INDEX")
ICLOUD_2SA_SEND_CODE = os.environ.get("ICLOUD_2SA_SEND_CODE", "1")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("icloud-glacier-backup")

# ---- Helpers ----
def _log_cookie_dir(cookie_dir: Path):
    try:
        files = list(cookie_dir.glob("*"))
        if not files:
            log.warning("Cookie-Verzeichnis ist leer: %s", cookie_dir)
        else:
            names = ", ".join(f.name for f in files[:10])
            more = "" if len(files) <= 10 else f" (+{len(files)-10} weitere)"
            log.info("Cookie-Dateien in %s: %s%s", cookie_dir, names, more)
    except Exception as e:
        log.debug("Cookie-Verzeichnis konnte nicht gelistet werden: %s", e)

def _persist_session(api):
    for attr in ("save_session", "_store_session", "persist_session"):
        fn = getattr(api, attr, None)
        if callable(fn):
            try:
                fn()
                log.info("Session über %s() persistiert.", attr)
                return
            except Exception as e:
                log.debug("Persist via %s() fehlgeschlagen: %s", attr, e)
    try:
        cj = getattr(api, "session", None)
        cj = getattr(cj, "cookies", None)
        if hasattr(cj, "save"):
            cj.save()
            log.info("Session-Cookies via cookiejar.save() persistiert.")
    except Exception as e:
        log.debug("cookiejar.save() fehlgeschlagen: %s", e)

def _read_code_from_file():
    try:
        code_path = Path('/state/2fa_code.txt')
        if code_path.exists():
            val = code_path.read_text(encoding='utf-8').strip()
            if val:
                try: code_path.unlink()
                except Exception: pass
                log.info("2FA/2SA-Code aus /state/2fa_code.txt verwendet.")
                return val
    except Exception as e:
        log.debug("Konnte /state/2fa_code.txt nicht lesen: %s", e)
    return None

def _prompt(label: str, secret: bool = False) -> str:
    if not sys.stdin.isatty():
        return ""
    try:
        return (getpass.getpass(label + ": ") if secret else input(label + ": ")).strip()
    except Exception:
        return ""

# ---- DB ----
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
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

# ---- iCloud ----
def connect_icloud() -> PyiCloudService:
    if not APPLE_ID or not APPLE_PASSWORD:
        log.error("APPLE_ID und APPLE_PASSWORD müssen gesetzt sein.")
        sys.exit(2)

    cookie_dir = Path(ICLOUD_COOKIE_DIR)
    cookie_dir.mkdir(parents=True, exist_ok=True)

    _log_cookie_dir(cookie_dir)
    api = PyiCloudService(APPLE_ID, APPLE_PASSWORD, cookie_directory=str(cookie_dir))

    # 1) Trusted session?
    is_trusted_fn = getattr(api, "is_trusted_session", None)
    if callable(is_trusted_fn):
        try:
            if api.is_trusted_session():
                log.info("Trusted Session gefunden – keine 2FA erforderlich.")
                _persist_session(api)
                _log_cookie_dir(cookie_dir)
                return api
        except Exception as e:
            log.debug("is_trusted_session() check fehlgeschlagen: %s", e)

    def obtain_code(prompt_label: str) -> str:
        return (
            ICLOUD_2FA_CODE
            or os.environ.get("ICLOUD_2SA_CODE")
            or _read_code_from_file()
            or _prompt(prompt_label, secret=True)
            or ""
        )

    # 2) 2FA flow
    if bool(getattr(api, "requires_2fa", False)):
        log.warning("2FA erforderlich.")
        validate_2fa = getattr(api, "validate_2fa_code", None)
        code_val = obtain_code("Bitte 2FA-Code eingeben")
        if not code_val:
            raise SystemExit("Kein 2FA-Code verfügbar. Setze ICLOUD_2FA_CODE oder starte interaktiv (-it).")
        if callable(validate_2fa):
            if not validate_2fa(code_val):
                raise SystemExit("2FA-Code ungültig.")
        trust = getattr(api, "trust_session", None)
        if callable(trust):
            try:
                trust()
                log.info("Session als trusted markiert (2FA).")
            except Exception as e:
                log.warning("trust_session() fehlgeschlagen: %s", e)
        _persist_session(api)
        _log_cookie_dir(cookie_dir)
        return api

    # 3) 2SA flow
    if bool(getattr(api, "requires_2sa", False)):
        log.warning("2-Schritt-Bestätigung (2SA) erforderlich.")
        devices = getattr(api, "trusted_devices", [])
        if not devices:
            raise SystemExit("Keine trusted_devices gefunden – prüfe Apple-ID auf einem Gerät.")
        if sys.stdin.isatty():
            for i, d in enumerate(devices):
                desc = d.get("deviceName") or d.get("deviceType") or str(d)
                print(f"[{i}] {desc}")
        try:
            idx = int(ICLOUD_2SA_DEVICE_INDEX) if ICLOUD_2SA_DEVICE_INDEX else 0
        except Exception:
            idx = 0
        if sys.stdin.isatty():
            typed = _prompt("Geräteindex für 2SA wählen (Enter=0)")
            if typed.isdigit():
                idx = int(typed)
        device = devices[min(max(idx, 0), len(devices)-1)]
        send = ICLOUD_2SA_SEND_CODE not in ("0", "false", "False")
        if sys.stdin.isatty():
            ans = _prompt("Verifizierungscode an Gerät senden? [Y/n]").lower()
            send = False if ans == "n" else True
        if send and not api.send_verification_code(device):
            raise SystemExit("Senden des 2SA-Codes fehlgeschlagen.")
        code_val = obtain_code("Bitte 2SA/Verification-Code eingeben")
        if not code_val:
            raise SystemExit("Kein 2SA-Code verfügbar. Setze ICLOUD_2FA_CODE/ICLOUD_2SA_CODE oder starte interaktiv (-it).")
        if not api.validate_verification_code(device, code_val):
            raise SystemExit("2SA/Verification-Code ungültig.")
        trust = getattr(api, "trust_session", None)
        if callable(trust):
            try:
                trust()
                log.info("Session als trusted markiert (2SA).")
            except Exception as e:
                log.warning("trust_session() fehlgeschlagen: %s", e)
        _persist_session(api)
        _log_cookie_dir(cookie_dir)
        return api

    _persist_session(api)
    _log_cookie_dir(cookie_dir)
    return api

# ---- S3 ----
def s3_client():
    return boto3.client("s3", region_name=AWS_REGION, config=BotoConfig(retries={"max_attempts": 10, "mode": "standard"}, connect_timeout=30, read_timeout=300))

def s3_object_exists(s3, bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key); return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"): return False
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
    ); conn.commit()

def already_uploaded(conn, asset_id: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM uploads WHERE asset_id=?", (asset_id,)).fetchone())

def build_s3_key(asset, filename: str) -> str:
    dt = getattr(asset, "asset_date", None) or getattr(asset, "created", None) or datetime.utcnow()
    try: year, month = dt.year, dt.month
    except Exception:
        try:
            from datetime import datetime as _dt
            _dt2 = _dt.fromisoformat(str(dt)); year, month = _dt2.year, _dt2.month
        except Exception:
            year, month = 1970, 1
    asset_id = getattr(asset, "id", None) or getattr(asset, "guid", None) or "unknownid"
    return f"{S3_PREFIX}/{year:04d}/{month:02d}/{asset_id}_{filename}"

# ---- Main pass ----
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
            log.warning("Überspringe Asset ohne ID (Datei: %s)", filename); skipped += 1; continue
        if already_uploaded(conn, asset_id):
            skipped += 1; continue
        key = build_s3_key(asset, filename)
        if s3_object_exists(s3, S3_BUCKET, key):
            log.info("Schon in S3 vorhanden, trage in DB ein: %s", key)
            mark_uploaded(conn, asset_id, key, size=0, md5_hex=""); skipped += 1; continue
        try:
            dl = asset.download()
            stream = dl.iter_content(chunk_size=1024*1024) if hasattr(dl, "iter_content") else (getattr(dl, "response", None) or getattr(dl, "raw", None) or dl).iter_content(chunk_size=1024*1024)
            with tempfile.NamedTemporaryFile(prefix="icloud_", suffix="_asset", delete=False) as tmp:
                tmp_path = tmp.name
                for chunk in stream:
                    if chunk: tmp.write(chunk)
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
            log.error(str(e)); time.sleep(120)
        except Exception as e:
            log.exception("Unerwarteter Fehler im Durchlauf: %s", e); time.sleep(300)
        else:
            log.info("Warte %s Sekunden bis zum nächsten Durchlauf ...", LOOP_INTERVAL_SECONDS); time.sleep(LOOP_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()

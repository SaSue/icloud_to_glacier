
#!/usr/bin/env python3
# iCloud → S3 incremental backup (v2.1)
# - Adds ROBUST DB MIGRATION for legacy `uploads` (no `variant` column)
# - Exports ORIGINAL + CURRENT (edited if available)
# - Sidecar metadata JSON
# - Interactive 2FA/2SA; trusted-session cookies; heartbeat logs

import os, sys, time, json, logging, sqlite3, tempfile, hashlib, getpass
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

S3_SSE = os.environ.get("S3_SSE")  # "AES256" oder "aws:kms"
S3_SSE_KMS_KEY_ID = os.environ.get("S3_SSE_KMS_KEY_ID")

EXPORT_METADATA = os.environ.get("EXPORT_METADATA", "sidecar").lower()  # "sidecar" | "none"
SIDECAR_STORAGE_CLASS = os.environ.get("SIDECAR_STORAGE_CLASS", "STANDARD")
ALBUMS_SCAN = os.environ.get("ALBUMS_SCAN", "false").lower() not in ("0","false","no")
ALBUMS_INDEX_PREFIX = os.environ.get("ALBUMS_INDEX_PREFIX", "_albums").strip("/")

LOOP_INTERVAL_SECONDS = int(os.environ.get("LOOP_INTERVAL_SECONDS", "21600"))
MAX_ASSETS_PER_RUN = int(os.environ.get("MAX_ASSETS_PER_RUN", "0"))
STARTUP_TEST_LIMIT = int(os.environ.get("STARTUP_TEST_LIMIT", "0"))
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

# ---- Helpers ----
def _stage(msg: str): log.info("STAGE | %s", msg)

def _heartbeat(tag: str, every: int = 5):
    if not hasattr(_heartbeat, "_last"): _heartbeat._last = 0
    now = time.time()
    if now - _heartbeat._last >= every:
        log.info("HEARTBEAT | %s ...", tag)
        _heartbeat._last = now

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
                fn(); log.info("Session über %s() persistiert.", attr); return
            except Exception as e:
                log.debug("Persist via %s() fehlgeschlagen: %s", attr, e)
    try:
        cj = getattr(api, "session", None); cj = getattr(cj, "cookies", None)
        if hasattr(cj, "save"): cj.save(); log.info("Session-Cookies via cookiejar.save() persistiert.")
    except Exception as e:
        log.debug("cookiejar.save() fehlgeschlagen: %s", e)

def _read_code_from_file():
    try:
        p = Path('/state/2fa_code.txt')
        if p.exists():
            val = p.read_text(encoding='utf-8').strip()
            if val:
                try: p.unlink()
                except Exception: pass
                log.info("2FA/2SA-Code aus /state/2fa_code.txt verwendet.")
                return val
    except Exception as e:
        log.debug("Konnte /state/2fa_code.txt nicht lesen: %s", e)
    return None

def _prompt(label: str, secret: bool = False) -> str:
    if not sys.stdin.isatty(): return ""
    try: return (getpass.getpass(label + ": ") if secret else input(label + ": ")).strip()
    except Exception: return ""

def md5_of_file(path: str, chunk: int = 1024*1024) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(chunk), b""): h.update(c)
    return h.hexdigest()

# ---- DB with robust migration ----
def _table_columns(conn, table: str):
    try: return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    except Exception: return []

def _migrate_legacy_uploads(conn):
    cols = _table_columns(conn, "uploads")
    if not cols:
        return  # no table yet
    if "variant" in cols:
        return  # already new schema
    log.info("Migration erkannt: 'uploads' ohne Spalte 'variant' → migriere auf neues Schema.")
    conn.execute("ALTER TABLE uploads RENAME TO uploads_old")
    conn.execute("""
        CREATE TABLE uploads (
            asset_id TEXT,
            variant  TEXT,
            s3_key   TEXT NOT NULL,
            size     INTEGER,
            md5_hex  TEXT,
            uploaded_at TEXT NOT NULL,
            PRIMARY KEY (asset_id, variant)
        )
    """)
    # Übernahme alter Daten als 'original'
    try:
        conn.execute("""
            INSERT OR IGNORE INTO uploads (asset_id, variant, s3_key, size, md5_hex, uploaded_at)
            SELECT asset_id, 'original', s3_key, COALESCE(size,0), COALESCE(md5_hex,''), COALESCE(uploaded_at, datetime('now'))
            FROM uploads_old
        """)
    except Exception as e:
        log.warning("Migration: Datenübernahme schlug fehl: %s", e)
    conn.execute("DROP TABLE IF EXISTS uploads_old")
    conn.commit()
    log.info("Migration abgeschlossen.")

def init_db(db_path: str):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    # falls Tabelle existiert: migrieren; sonst neu erzeugen
    existing = _table_columns(conn, "uploads")
    if existing:
        _migrate_legacy_uploads(conn)
    else:
        conn.execute("""
            CREATE TABLE uploads (
                asset_id TEXT,
                variant  TEXT,
                s3_key   TEXT NOT NULL,
                size     INTEGER,
                md5_hex  TEXT,
                uploaded_at TEXT NOT NULL,
                PRIMARY KEY (asset_id, variant)
            )
        """); conn.commit()
    return conn

def mark_uploaded(conn, asset_id: str, variant: str, key: str, size: int, md5_hex: str):
    conn.execute(
        "INSERT OR REPLACE INTO uploads (asset_id, variant, s3_key, size, md5_hex, uploaded_at) VALUES (?,?,?,?,?,?)",
        (asset_id, variant, key, size, md5_hex, datetime.utcnow().isoformat(timespec="seconds")),
    ); conn.commit()

def already_uploaded(conn, asset_id: str, variant: str) -> bool:
    cur = conn.execute("SELECT 1 FROM uploads WHERE asset_id=? AND variant=?", (asset_id, variant))
    return bool(cur.fetchone())

# ---- iCloud ----
def connect_icloud() -> PyiCloudService:
    if not APPLE_ID or not APPLE_PASSWORD:
        log.error("APPLE_ID und APPLE_PASSWORD müssen gesetzt sein."); sys.exit(2)
    cookie_dir = Path(ICLOUD_COOKIE_DIR); cookie_dir.mkdir(parents=True, exist_ok=True)
    _log_cookie_dir(cookie_dir)
    api = PyiCloudService(APPLE_ID, APPLE_PASSWORD, cookie_directory=str(cookie_dir))
    is_trusted_fn = getattr(api, "is_trusted_session", None)
    if callable(is_trusted_fn):
        try:
            if api.is_trusted_session():
                log.info("Trusted Session gefunden – keine 2FA erforderlich.")
                _persist_session(api); _log_cookie_dir(cookie_dir); return api
        except Exception as e:
            log.debug("is_trusted_session() check fehlgeschlagen: %s", e)
    def obtain_code(prompt_label: str) -> str:
        return (ICLOUD_2FA_CODE or os.environ.get("ICLOUD_2SA_CODE") or _read_code_from_file() or _prompt(prompt_label, secret=True) or "")
    if bool(getattr(api, "requires_2fa", False)):
        log.warning("2FA erforderlich.")
        validate_2fa = getattr(api, "validate_2fa_code", None)
        code_val = obtain_code("Bitte 2FA-Code eingeben")
        if not code_val: raise SystemExit("Kein 2FA-Code verfügbar. Setze ICLOUD_2FA_CODE oder starte interaktiv (-it).")
        if callable(validate_2fa) and not validate_2fa(code_val): raise SystemExit("2FA-Code ungültig.")
        trust = getattr(api, "trust_session", None)
        if callable(trust):
            try: trust(); log.info("Session als trusted markiert (2FA).")
            except Exception as e: log.warning("trust_session() fehlgeschlagen: %s", e)
        _persist_session(api); _log_cookie_dir(cookie_dir); return api
    if bool(getattr(api, "requires_2sa", False)):
        log.warning("2-Schritt-Bestätigung (2SA) erforderlich.")
        devices = getattr(api, "trusted_devices", [])
        if not devices: raise SystemExit("Keine trusted_devices gefunden – prüfe Apple-ID auf einem Gerät.")
        if sys.stdin.isatty():
            for i, d in enumerate(devices):
                desc = d.get("deviceName") or d.get("deviceType") or str(d); print(f"[{i}] {desc}")
        try: idx = int(ICLOUD_2SA_DEVICE_INDEX) if ICLOUD_2SA_DEVICE_INDEX else 0
        except Exception: idx = 0
        if sys.stdin.isatty():
            typed = _prompt("Geräteindex für 2SA wählen (Enter=0)"); 
            if typed.isdigit(): idx = int(typed)
        device = devices[min(max(idx, 0), len(devices)-1)]
        send = ICLOUD_2SA_SEND_CODE not in ("0", "false", "False")
        if sys.stdin.isatty():
            ans = _prompt("Verifizierungscode an Gerät senden? [Y/n]").lower(); send = False if ans == "n" else True
        if send and not api.send_verification_code(device): raise SystemExit("Senden des 2SA-Codes fehlgeschlagen.")
        code_val = obtain_code("Bitte 2SA/Verification-Code eingeben")
        if not code_val: raise SystemExit("Kein 2SA-Code verfügbar. Setze ICLOUD_2FA_CODE/ICLOUD_2SA_CODE oder starte interaktiv (-it).")
        if not api.validate_verification_code(device, code_val): raise SystemExit("2SA/Verification-Code ungültig.")
        trust = getattr(api, "trust_session", None)
        if callable(trust):
            try: trust(); log.info("Session als trusted markiert (2SA).")
            except Exception as e: log.warning("trust_session() fehlgeschlagen: %s", e)
        _persist_session(api); _log_cookie_dir(cookie_dir); return api
    _persist_session(api); _log_cookie_dir(cookie_dir); return api

# ---- S3 ----
def s3_client():
    return boto3.client("s3", region_name=AWS_REGION, config=BotoConfig(retries={"max_attempts": 10, "mode": "standard"}, connect_timeout=30, read_timeout=300))

def s3_upload_bytes(s3, data: bytes, key: str, storage_class: str = None, extra_meta: dict = None):
    args = {}
    if storage_class: args["StorageClass"] = storage_class
    if S3_SSE:
        args["ServerSideEncryption"] = S3_SSE
        if S3_SSE == "aws:kms" and S3_SSE_KMS_KEY_ID: args["SSEKMSKeyId"] = S3_SSE_KMS_KEY_ID
    if extra_meta: args["Metadata"] = {k:str(v)[:200] for k,v in extra_meta.items()}
    s3.put_object(Bucket=S3_BUCKET, Key=key, Body=data, **args)

def s3_upload_file(s3, local_path: str, key: str, storage_class: str = None, extra_meta: dict = None):
    extra = {}
    if storage_class: extra["StorageClass"] = storage_class
    if S3_SSE:
        extra["ServerSideEncryption"] = S3_SSE
        if S3_SSE == "aws:kms" and S3_SSE_KMS_KEY_ID: extra["SSEKMSKeyId"] = S3_SSE_KMS_KEY_ID
    if extra_meta: extra["Metadata"] = {k:str(v)[:200] for k,v in extra_meta.items()}
    s3.upload_file(local_path, S3_BUCKET, key, ExtraArgs=extra)

def s3_object_exists(s3, bucket: str, key: str) -> bool:
    try: s3.head_object(Bucket=bucket, Key=key); return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"): return False
        raise

# ---- Variant & keys ----
def choose_current_version_label(asset):
    versions = getattr(asset, "versions", {}) or {}
    if hasattr(versions, "keys"):
        keys = list(versions.keys()); lower_map = {k.lower(): k for k in keys}
        preferred = ["renderedfullsize","editedfullsize","adjustedfull","fullres","fullsize","full","original"]
        for token in preferred:
            if token in lower_map:
                key = lower_map[token]
                return ("current", key) if token != "original" else ("original", key)
        for token in preferred:
            for k in keys:
                name = k.replace("_","").replace("-","").lower()
                if token in name:
                    return ("current", k) if token != "original" else ("original", k)
        if keys: return ("original", keys[0])
    return ("original", "original")

def build_key_legacy(asset, filename: str) -> str:
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

def build_key_variant(asset, filename: str, variant: str) -> str:
    dt = getattr(asset, "asset_date", None) or getattr(asset, "created", None) or datetime.utcnow()
    try: year, month = dt.year, dt.month
    except Exception:
        try:
            from datetime import datetime as _dt
            _dt2 = _dt.fromisoformat(str(dt)); year, month = _dt2.year, _dt2.month
        except Exception:
            year, month = 1970, 1
    asset_id = getattr(asset, "id", None) or getattr(asset, "guid", None) or "unknownid"
    return f"{S3_PREFIX}/{year:04d}/{month:02d}/{asset_id}_{variant}_{filename}"

# ---- Sidecar ----
def extract_asset_metadata(asset) -> dict:
    md = {}
    def g(name, default=None): return getattr(asset, name, default)
    md["id"] = g("id") or g("guid")
    md["filename"] = g("filename")
    md["created"] = str(g("created", ""))
    md["added"] = str(getattr(asset, "added", ""))
    md["modified"] = str(getattr(asset, "modified", ""))
    md["dimensions"] = {"width": g("width"), "height": g("height")}
    md["duration"] = g("duration", None)
    md["orientation"] = g("orientation", None)
    loc = getattr(asset, "location", None)
    if isinstance(loc, dict):
        md["location"] = {k: loc.get(k) for k in ("latitude","longitude","altitude") if k in loc}
    elif loc:
        md["location"] = str(loc)
    versions = getattr(asset, "versions", {}) or {}
    try: md["versions"] = list(versions.keys())
    except Exception: md["versions"] = []
    md["is_favorite"] = bool(getattr(asset, "is_favorite", False))
    md["is_hidden"] = bool(getattr(asset, "is_hidden", False))
    return md

def make_sidecar(asset, variant: str, s3_key: str, size: int, md5_hex: str, albums_for_asset: list) -> bytes:
    base = extract_asset_metadata(asset)
    base.update({
        "asset_id": base.get("id"),
        "variant": variant,
        "s3_key": s3_key,
        "backup": {"size": size, "md5_hex": md5_hex, "uploaded_at": datetime.utcnow().isoformat(timespec="seconds")},
        "albums": albums_for_asset or []
    })
    return (json.dumps(base, ensure_ascii=False, separators=(",",":")) + "\n").encode("utf-8")

# ---- Albums scan (optional) ----
def build_albums_membership(api):
    _stage("Album-Scan gestartet (ALBUMS_SCAN=true)")
    membership = {}; albums = getattr(api.photos, "albums", {})
    for album_name, album in getattr(albums, "items", lambda: [])():
        _stage(f"Scanne Album: {album_name}")
        for asset in album:
            aid = getattr(asset, "id", None) or getattr(asset, "guid", None)
            if not aid: continue
            arr = membership.setdefault(aid, [])
            album_id = getattr(album, "id", None) or album_name
            arr.append({"album_id": str(album_id), "album_name": album_name})
            _heartbeat("Album-Scan")
    _stage("Album-Scan fertig"); return membership

# ---- Main pass ----
def process_once():
    _stage('Beginne Durchlauf')
    api = connect_icloud(); _stage('iCloud verbunden')
    conn = init_db(STATE_DB_PATH); _stage('Datenbank OK')
    s3 = s3_client(); _stage('S3-Client OK')

    albums_membership = {}
    if ALBUMS_SCAN:
        try: albums_membership = build_albums_membership(api)
        except Exception as e: log.warning("Album-Scan fehlgeschlagen/übersprungen: %s", e)

    _stage('Ermittle Foto-Iterator')
    iterator = None
    try:
        albums = getattr(api.photos, "albums", None)
        if albums and hasattr(albums, "get"):
            all_photos = api.photos.albums.get("All Photos")
            if all_photos:
                iterator = all_photos; log.info("Nutze Album-Iterator: All Photos")
        if iterator is None:
            iterator = api.photos.all; log.info("Nutze globalen Iterator: photos.all")
    except Exception as e:
        log.warning("Konnte Album 'All Photos' nicht ermitteln: %s – nutze photos.all", e)
        iterator = api.photos.all

    _stage('Starte Iteration')
    processed = skipped = uploaded = 0; count = 0
    for asset in iterator:
        _heartbeat('Listing/Download'); count += 1
        if STARTUP_TEST_LIMIT and count > STARTUP_TEST_LIMIT:
            log.info('STARTUP_TEST_LIMIT=%s erreicht – vorzeitig abbrechen.', STARTUP_TEST_LIMIT); break

        asset_id = getattr(asset, "id", None) or getattr(asset, "guid", None)
        filename = getattr(asset, "filename", None) or f"{asset_id or 'asset'}.bin"
        if not asset_id:
            log.warning("Überspringe Asset ohne ID (Datei: %s)", filename); skipped += 1; continue

        plan = [("original","original")]
        cur_variant, cur_key = choose_current_version_label(asset)
        if not (cur_variant == "original" and cur_key == "original"):
            plan.append((cur_variant, cur_key))

        albums_for_asset = albums_membership.get(asset_id) if albums_membership else []

        for variant, version_key in plan:
            try:
                if already_uploaded(conn, asset_id, variant):
                    skipped += 1; continue

                new_key = build_key_variant(asset, filename, variant)
                legacy_key = build_key_legacy(asset, filename) if variant == "original" else None

                if legacy_key and s3_object_exists(s3, S3_BUCKET, legacy_key):
                    log.info("Migration: Fand legacy-Objekt, übernehme ohne Neu-Upload: %s", legacy_key)
                    mark_uploaded(conn, asset_id, "original", legacy_key, size=0, md5_hex="")
                    if EXPORT_METADATA == "sidecar":
                        sidecar = make_sidecar(asset, "original", legacy_key, size=0, md5_hex="", albums_for_asset=albums_for_asset)
                        s3_upload_bytes(s3, sidecar, legacy_key + ".json", storage_class=SIDECAR_STORAGE_CLASS,
                                        extra_meta={"asset-id": asset_id, "variant": "original"})
                    skipped += 1; continue

                try: dl = asset.download(version_key)
                except TypeError: dl = asset.download()
                if hasattr(dl, "iter_content"):
                    stream = dl.iter_content(chunk_size=1024*1024)
                else:
                    resp = getattr(dl, "response", None) or getattr(dl, "raw", None) or dl
                    stream = resp.iter_content(chunk_size=1024*1024)

                with tempfile.NamedTemporaryFile(prefix=f"icloud_{variant}_", suffix="_asset", delete=False) as tmp:
                    tmp_path = tmp.name
                    for chunk in stream:
                        if chunk: tmp.write(chunk)

                size = os.path.getsize(tmp_path); md5_hex = md5_of_file(tmp_path)
                s3_upload_file(s3, tmp_path, new_key, storage_class=S3_STORAGE_CLASS,
                               extra_meta={"asset-id": asset_id, "variant": variant})
                mark_uploaded(conn, asset_id, variant, new_key, size=size, md5_hex=md5_hex)
                uploaded += 1
                log.info("Hochgeladen (%s, %s): %s (%s bytes) -> s3://%s/%s", variant, version_key, filename, size, S3_BUCKET, new_key)

                if EXPORT_METADATA == "sidecar":
                    sidecar = make_sidecar(asset, variant, new_key, size=size, md5_hex=md5_hex, albums_for_asset=albums_for_asset)
                    s3_upload_bytes(s3, sidecar, new_key + ".json", storage_class=SIDECAR_STORAGE_CLASS,
                                    extra_meta={"asset-id": asset_id, "variant": variant})

            except ClientError as e:
                log.error("AWS S3 Fehler bei %s (%s): %s", filename, variant, e)
            except Exception as e:
                log.error("Fehler bei %s (%s): %s", filename, variant, e)
            finally:
                try:
                    if "tmp_path" in locals() and os.path.exists(tmp_path): os.remove(tmp_path)
                except Exception: pass

        processed += 1
        if MAX_ASSETS_PER_RUN and processed >= MAX_ASSETS_PER_RUN:
            log.info("MAX_ASSETS_PER_RUN erreicht (%s).", MAX_ASSETS_PER_RUN); break

    _stage('Durchlauf fertig')
    log.info("Durchlauf beendet. verarbeitet=%s, hochgeladen=%s, übersprungen=%s", processed, uploaded, skipped)

def main():
    while True:
        try: process_once()
        except SystemExit as e:
            log.error(str(e)); time.sleep(120)
        except Exception as e:
            log.exception("Unerwarteter Fehler im Durchlauf: %s", e); time.sleep(300)
        else:
            log.info("Warte %s Sekunden bis zum nächsten Durchlauf ...", LOOP_INTERVAL_SECONDS); time.sleep(LOOP_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()

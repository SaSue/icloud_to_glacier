# im Projektordner ausführen:
#!/usr/bin/env python3
# iCloud → S3 incremental backup (v2.4)
# - ALWAYS back up ORIGINAL + LATEST (edited/rendered if available)
# - BACKFILL: für bereits hochgeladene ORIGINALs fehlendes Sidecar (.json) nachladen
# - BACKFILL: wenn bisher nur ORIGINAL existiert, versuchen eine bearbeitete Variante als LATEST zu ergänzen
# - DB auto-migration: legacy schema → variant; 'current' wird ohne Re-Upload als 'latest' übernommen
# - Sidecar-Metadaten pro Variante
# - Interaktive 2FA/2SA möglich; trusted cookies

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
S3_SSE = os.environ.get("S3_SSE")                      # "AES256" oder "aws:kms"
S3_SSE_KMS_KEY_ID = os.environ.get("S3_SSE_KMS_KEY_ID")

EXPORT_METADATA = os.environ.get("EXPORT_METADATA", "sidecar").lower()  # sidecar|none
SIDECAR_STORAGE_CLASS = os.environ.get("SIDECAR_STORAGE_CLASS", "STANDARD")
ALBUMS_SCAN = os.environ.get("ALBUMS_SCAN", "false").lower() not in ("0","false","no")

LOOP_INTERVAL_SECONDS = int(os.environ.get("LOOP_INTERVAL_SECONDS", "21600"))
MAX_ASSETS_PER_RUN   = int(os.environ.get("MAX_ASSETS_PER_RUN", "0"))
STARTUP_TEST_LIMIT   = int(os.environ.get("STARTUP_TEST_LIMIT", "0"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# Detection/Debug knobs
# (env-Name bleibt für Rückwärtskompatibilität)
LATEST_KEYS_HINT = [k.strip() for k in os.environ.get("CURRENT_VERSION_KEYS_HINT","").split(",") if k.strip()]
FORCE_SAVE_LATEST = os.environ.get("FORCE_SAVE_LATEST","true").lower() in ("1","true","yes")
DUMP_VERSIONS_FIRST_N = int(os.environ.get("DUMP_VERSIONS_FIRST_N","20"))
MIGRATE_CURRENT_TO_LATEST = os.environ.get("MIGRATE_CURRENT_TO_LATEST","true").lower() in ("1","true","yes")

# 2FA/2SA
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
        log.info("HEARTBEAT | %s ...", tag); _heartbeat._last = now

def _log_cookie_dir(cookie_dir: Path):
    try:
        files = list(cookie_dir.glob("*"))
        if not files: log.warning("Cookie-Verzeichnis ist leer: %s", cookie_dir)
        else:
            names = ", ".join(f.name for f in files[:10])
            more = "" if len(files) <= 10 else f" (+%d weitere)" % (len(files)-10)
            log.info("Cookie-Dateien in %s: %s%s", cookie_dir, names, more)
    except Exception as e:
        log.debug("Cookie-Verzeichnis konnte nicht gelistet werden: %s", e)

def _persist_session(api):
    for attr in ("save_session", "_store_session", "persist_session"):
        fn = getattr(api, attr, None)
        if callable(fn):
            try: fn(); log.info("Session über %s() persistiert.", attr); return
            except Exception as e: log.debug("Persist via %s() fehlgeschlagen: %s", attr, e)
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

# ---- DB & Migration ----
def _table_columns(conn, table: str):
    try: return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    except Exception: return []

def _migrate_legacy_uploads(conn):
    cols = _table_columns(conn, "uploads")
    if not cols: return
    if "variant" in cols: return
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
    conn.execute("""
        INSERT OR IGNORE INTO uploads (asset_id, variant, s3_key, size, md5_hex, uploaded_at)
        SELECT asset_id, 'original', s3_key, COALESCE(size,0), COALESCE(md5_hex,''), COALESCE(uploaded_at, datetime('now'))
        FROM uploads_old
    """)
    conn.execute("DROP TABLE uploads_old"); conn.commit()
    log.info("Migration (legacy schema) abgeschlossen.")

def _adopt_current_to_latest(conn):
    if not MIGRATE_CURRENT_TO_LATEST: return
    try:
        cur = conn.execute("SELECT asset_id, s3_key, size, md5_hex, uploaded_at FROM uploads WHERE variant='current'")
        rows = cur.fetchall()
        if not rows: return
        log.info("Migration: %d Einträge 'current' → 'latest' übernehmen.", len(rows))
        for asset_id, s3_key, size, md5_hex, uploaded_at in rows:
            conn.execute(
                "INSERT OR IGNORE INTO uploads (asset_id, variant, s3_key, size, md5_hex, uploaded_at) VALUES (?,?,?,?,?,?)",
                (asset_id, "latest", s3_key, size or 0, md5_hex or "", uploaded_at or datetime.utcnow().isoformat(timespec="seconds"))
            )
        conn.commit()
        log.info("Migration (current→latest) abgeschlossen.")
    except Exception as e:
        log.warning("Migration (current→latest) fehlgeschlagen: %s", e)

def init_db(db_path: str):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    if _table_columns(conn, "uploads"):
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
    _adopt_current_to_latest(conn)
    return conn

def mark_uploaded(conn, asset_id: str, variant: str, key: str, size: int, md5_hex: str):
    conn.execute(
        "INSERT OR REPLACE INTO uploads (asset_id, variant, s3_key, size, md5_hex, uploaded_at) VALUES (?,?,?,?,?,?)",
        (asset_id, variant, key, size, md5_hex, datetime.utcnow().isoformat(timespec="seconds")),
    ); conn.commit()

def already_uploaded(conn, asset_id: str, variant: str) -> bool:
    cur = conn.execute("SELECT 1 FROM uploads WHERE asset_id=? AND variant=?", (asset_id, variant))
    return bool(cur.fetchone())

def get_uploaded_entry(conn, asset_id: str, variant: str):
    cur = conn.execute("SELECT s3_key, size, md5_hex, uploaded_at FROM uploads WHERE asset_id=? AND variant=?", (asset_id, variant))
    return cur.fetchone()

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
            typed = _prompt("Geräteindex für 2SA wählen (Enter=0)")
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
    return boto3.client(
        "s3",
        region_name=AWS_REGION,
        config=BotoConfig(retries={"max_attempts": 10, "mode": "standard"}, connect_timeout=30, read_timeout=300),
    )

def s3_upload_bytes(s3, data: bytes, key: str, storage_class: str = None, extra_meta: dict = None):
    args = {}
    if storage_class: args["StorageClass"] = storage_class
    if S3_SSE:
        args["ServerSideEncryption"] = S3_SSE
        if S3_SSE == "aws:kms" and S3_SSE_KMS_KEY_ID: args["SSEKMSKeyId"] = S3_SSE_KMS_KEY_ID
    if extra_meta: args["Metadata"] = {k: str(v)[:200] for k, v in extra_meta.items()}
    s3.put_object(Bucket=S3_BUCKET, Key=key, Body=data, **args)

def s3_upload_file(s3, local_path: str, key: str, storage_class: str = None, extra_meta: dict = None):
    extra = {}
    if storage_class: extra["StorageClass"] = storage_class
    if S3_SSE:
        extra["ServerSideEncryption"] = S3_SSE
        if S3_SSE == "aws:kms" and S3_SSE_KMS_KEY_ID: extra["SSEKMSKeyId"] = S3_SSE_KMS_KEY_ID
    if extra_meta: extra["Metadata"] = {k: str(v)[:200] for k, v in extra_meta.items()}
    s3.upload_file(local_path, S3_BUCKET, key, ExtraArgs=extra)

def s3_object_exists(s3, bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key); return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"): return False
        raise

# ---- Latest detection ----
COMMON_LATEST_KEYS = ["renderedFullSize","editedFullSize","adjustedFull","fullres","fullsize","full"]

def choose_latest_version_key(asset):
    versions = getattr(asset, "versions", {}) or {}
    keys = list(versions.keys()) if hasattr(versions, "keys") else []
    lower_map = {k.lower(): k for k in keys}
    if DUMP_VERSIONS_FIRST_N > 0:
        if not hasattr(choose_latest_version_key, "_dumped"): choose_latest_version_key._dumped = 0
        if choose_latest_version_key._dumped < DUMP_VERSIONS_FIRST_N:
            log.info("VERSIONS | %s", keys)
            choose_latest_version_key._dumped += 1
    # Hints
    for h in LATEST_KEYS_HINT:
        if lower_map.get(h.lower()): return lower_map[h.lower()]
    # Common
    for token in COMMON_LATEST_KEYS:
        k = lower_map.get(token.lower())
        if k: return k
    # Fuzzy
    for token in COMMON_LATEST_KEYS:
        for k in keys:
            nm = k.replace("_","").replace("-","").lower()
            if token.lower() in nm: return k
    # Heuristik: adjusted?
    is_adj = False
    for att in ("is_adjusted","isEdited","is_edited"):
        try: is_adj = is_adj or bool(getattr(asset, att, False))
        except Exception: pass
    if not is_adj:
        for att in ("_data","_asset","_photo"):
            d = getattr(asset, att, None)
            if isinstance(d, dict) and any(k in d for k in ("adjustmentRenderURL","adjustmentType","isEdited","is_adjusted")):
                is_adj = True; break
    if is_adj and keys: return keys[-1]
    return "original"

def download_variant(api_asset, version_key):
    tried = []
    def _try(key):
        try: return api_asset.download(key)
        except TypeError:
            if key is None: raise
            return None
        except Exception:
            return None
    for k in [version_key] + LATEST_KEYS_HINT + COMMON_LATEST_KEYS + ["original", None]:
        if k in tried: continue
        tried.append(k)
        dl = _try(k)
        if dl is not None:
            return dl, (k or "original")
    return api_asset.download(), "original"

# ---- Keys ----
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
    log.info("Album-Scan gestartet (ALBUMS_SCAN=true)")
    membership = {}; albums = getattr(api.photos, "albums", {})
    for album_name, album in getattr(albums, "items", lambda: [])():
        log.info("Scanne Album: %s", album_name)
        for asset in album:
            aid = getattr(asset, "id", None) or getattr(asset, "guid", None)
            if not aid: continue
            arr = membership.setdefault(aid, [])
            album_id = getattr(album, "id", None) or album_name
            arr.append({"album_id": str(album_id), "album_name": album_name})
            _heartbeat("Album-Scan")
    log.info("Album-Scan fertig"); return membership

# ---- Main pass ----
def process_once():
    log.info("STAGE | Beginne Durchlauf")
    api = connect_icloud(); log.info("STAGE | iCloud verbunden")
    conn = init_db(STATE_DB_PATH); log.info("STAGE | Datenbank OK")
    s3 = s3_client(); log.info("STAGE | S3-Client OK")

    # DB adopt: 'current' → 'latest'
    if MIGRATE_CURRENT_TO_LATEST:
        try:
            cur = conn.execute("SELECT COUNT(1) FROM uploads WHERE variant='current'")
            cnt = cur.fetchone()[0]
            if cnt:
                log.info("Adoptiere %d DB-Einträge von 'current' → 'latest'.", cnt)
                conn.execute("""
                    INSERT OR IGNORE INTO uploads (asset_id, variant, s3_key, size, md5_hex, uploaded_at)
                    SELECT asset_id, 'latest', s3_key, size, md5_hex, uploaded_at
                    FROM uploads WHERE variant='current'
                """); conn.commit()
        except Exception as e:
            log.warning("Adoption (current→latest) fehlgeschlagen: %s", e)

    albums_membership = {}
    if ALBUMS_SCAN:
        try: albums_membership = build_albums_membership(api)
        except Exception as e: log.warning("Album-Scan fehlgeschlagen/übersprungen: %s", e)

    log.info("STAGE | Ermittle Foto-Iterator")
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

    log.info("STAGE | Starte Iteration")
    processed = skipped = uploaded = 0; count = 0

    for asset in iterator:
        _heartbeat('Listing/Download'); count += 1
        if STARTUP_TEST_LIMIT and count > STARTUP_TEST_LIMIT:
            log.info('STARTUP_TEST_LIMIT=%s erreicht – vorzeitig abbrechen.', STARTUP_TEST_LIMIT); break

        asset_id = getattr(asset, "id", None) or getattr(asset, "guid", None)
        filename = getattr(asset, "filename", None) or f"{asset_id or 'asset'}.bin"
        if not asset_id:
            log.warning("Überspringe Asset ohne ID (Datei: %s)", filename); skipped += 1; continue

        # --- Varianten-Logging ---
        versions = getattr(asset, "versions", {}) or {}
        variant_keys = list(versions.keys()) if hasattr(versions, "keys") else []
        log.info("Asset %s: Gefundene Varianten: %s", asset_id, ", ".join(variant_keys) if variant_keys else "nur 'original'")

        albums_for_asset = albums_membership.get(asset_id) if albums_membership else []

        # ---- Ensure ORIGINAL ----
        have_original = already_uploaded(conn, asset_id, "original")
        if not have_original:
            # Migration: legacy S3 object?
            legacy_key = build_key_legacy(asset, filename)
            if s3_object_exists(s3, S3_BUCKET, legacy_key):
                log.info("Migration: Fand legacy-Objekt (original), übernehme ohne Neu-Upload: %s", legacy_key)
                mark_uploaded(conn, asset_id, "original", legacy_key, size=0, md5_hex="")
                # Sidecar für legacy ggf. nachziehen
                if EXPORT_METADATA == "sidecar" and not s3_object_exists(s3, S3_BUCKET, legacy_key + ".json"):
                    sidecar = make_sidecar(asset, "original", legacy_key, size=0, md5_hex="", albums_for_asset=albums_for_asset)
                    s3_upload_bytes(s3, sidecar, legacy_key + ".json", storage_class=SIDECAR_STORAGE_CLASS,
                                    extra_meta={"asset-id": asset_id, "variant": "original"})
            else:
                # Original herunterladen & hochladen
                try:
                    dl, used_key = download_variant(asset, "original")
                    if hasattr(dl, "iter_content"): stream = dl.iter_content(chunk_size=1024*1024)
                    else:
                        resp = getattr(dl, "response", None) or getattr(dl, "raw", None) or dl
                        stream = resp.iter_content(chunk_size=1024*1024)
                    with tempfile.NamedTemporaryFile(prefix="icloud_original_", suffix="_asset", delete=False) as tmp:
                        tmp_path = tmp.name
                        for chunk in stream:
                            if chunk: tmp.write(chunk)
                    size = os.path.getsize(tmp_path); md5_hex = md5_of_file(tmp_path)
                    new_key = build_key_variant(asset, filename, "original")
                    s3_upload_file(s3, tmp_path, new_key, storage_class=S3_STORAGE_CLASS,
                                   extra_meta={"asset-id": asset_id, "variant": "original"})
                    mark_uploaded(conn, asset_id, "original", new_key, size=size, md5_hex=md5_hex)
                    log.info("Hochgeladen (original, %s): %s (%s bytes) -> s3://%s/%s", used_key, filename, size, S3_BUCKET, new_key)
                    if EXPORT_METADATA == "sidecar":
                        sidecar = make_sidecar(asset, "original", new_key, size=size, md5_hex=md5_hex, albums_for_asset=albums_for_asset)
                        s3_upload_bytes(s3, sidecar, new_key + ".json", storage_class=SIDECAR_STORAGE_CLASS,
                                        extra_meta={"asset-id": asset_id, "variant": "original"})
                finally:
                    try:
                        if "tmp_path" in locals() and os.path.exists(tmp_path): os.remove(tmp_path)
                    except Exception: pass

        # ---- Backfill Sidecar für ORIGINAL falls fehlend ----
        row = get_uploaded_entry(conn, asset_id, "original")
        if row and EXPORT_METADATA == "sidecar":
            orig_key, size_saved, md5_saved, _ = row
            sidecar_key = orig_key + ".json"
            try:
                if not s3_object_exists(s3, S3_BUCKET, sidecar_key):
                    log.info("Backfill: Sidecar für ORIGINAL fehlt, lade nach: %s", sidecar_key)
                    sidecar = make_sidecar(asset, "original", orig_key, size=size_saved or 0, md5_hex=md5_saved or "", albums_for_asset=albums_for_asset)
                    s3_upload_bytes(s3, sidecar, sidecar_key, storage_class=SIDECAR_STORAGE_CLASS,
                                    extra_meta={"asset-id": asset_id, "variant": "original"})
            except Exception as e:
                log.warning("Sidecar-Backfill (original) fehlgeschlagen: %s", e)

        # ---- Ensure LATEST (bearbeitete Version) ----
        have_latest = already_uploaded(conn, asset_id, "latest")
        if not have_latest:
            latest_key_name = choose_latest_version_key(asset)
            if FORCE_SAVE_LATEST and latest_key_name == "original":
                latest_key_name = (LATEST_KEYS_HINT[0] if LATEST_KEYS_HINT else None)

            # DB-Adoption von 'current'
            try:
                cur = conn.execute("SELECT s3_key,size,md5_hex,uploaded_at FROM uploads WHERE asset_id=? AND variant='current'", (asset_id,))
                rowc = cur.fetchone()
                if rowc:
                    s3_key,size,md5_hex,uploaded_at = rowc
                    conn.execute(
                        "INSERT OR IGNORE INTO uploads (asset_id, variant, s3_key, size, md5_hex, uploaded_at) VALUES (?,?,?,?,?,?)",
                        (asset_id,"latest",s3_key,size or 0,md5_hex or "", uploaded_at or datetime.utcnow().isoformat(timespec="seconds"))
                    ); conn.commit()
                    have_latest = True
                    log.info("Adoptiere DB-Eintrag 'current' als 'latest' für %s", filename)
            except Exception:
                pass

            # S3-Adoption von '_current_' Key
            if not have_latest and latest_key_name and latest_key_name != "original":
                current_key = build_key_variant(asset, filename, "current")
                try:
                    if s3_object_exists(s3, S3_BUCKET, current_key):
                        log.info("Adoptiere vorhandenes S3 'current' als 'latest': %s", current_key)
                        mark_uploaded(conn, asset_id, "latest", current_key, size=0, md5_hex="")
                        if EXPORT_METADATA == "sidecar" and not s3_object_exists(s3, S3_BUCKET, current_key + ".json"):
                            sidecar = make_sidecar(asset, "latest", current_key, size=0, md5_hex="", albums_for_asset=albums_for_asset)
                            s3_upload_bytes(s3, sidecar, current_key + ".json", storage_class=SIDECAR_STORAGE_CLASS,
                                            extra_meta={"asset-id": asset_id, "variant": "latest"})
                        have_latest = True
                except Exception:
                    pass

            # Wenn weiterhin keine latest existiert, aber Erkennung liefert etwas ≠ original → hochladen
            if not have_latest and latest_key_name and latest_key_name != "original":
                try:
                    dl, used_key = download_variant(asset, latest_key_name)
                    if hasattr(dl, "iter_content"): stream = dl.iter_content(chunk_size=1024*1024)
                    else:
                        resp = getattr(dl, "response", None) or getattr(dl, "raw", None) or dl
                        stream = resp.iter_content(chunk_size=1024*1024)
                    with tempfile.NamedTemporaryFile(prefix="icloud_latest_", suffix="_asset", delete=False) as tmp:
                        tmp_path = tmp.name
                        for chunk in stream:
                            if chunk: tmp.write(chunk)
                    size = os.path.getsize(tmp_path); md5_hex = md5_of_file(tmp_path)
                    new_key = build_key_variant(asset, filename, "latest")
                    s3_upload_file(s3, tmp_path, new_key, storage_class=S3_STORAGE_CLASS,
                                   extra_meta={"asset-id": asset_id, "variant": "latest"})
                    mark_uploaded(conn, asset_id, "latest", new_key, size=size, md5_hex=md5_hex)
                    log.info("Hochgeladen (latest, %s): %s (%s bytes) -> s3://%s/%s", used_key, filename, size, S3_BUCKET, new_key)
                    if EXPORT_METADATA == "sidecar":
                        sidecar = make_sidecar(asset, "latest", new_key, size=size, md5_hex=md5_hex, albums_for_asset=albums_for_asset)
                        s3_upload_bytes(s3, sidecar, new_key + ".json", storage_class=SIDECAR_STORAGE_CLASS,
                                        extra_meta={"asset-id": asset_id, "variant": "latest"})
                finally:
                    try:
                        if "tmp_path" in locals() and os.path.exists(tmp_path): os.remove(tmp_path)
                    except Exception: pass

        processed += 1
        if MAX_ASSETS_PER_RUN and processed >= MAX_ASSETS_PER_RUN:
            log.info("MAX_ASSETS_PER_RUN erreicht (%s).", MAX_ASSETS_PER_RUN); break

    log.info("STAGE | Durchlauf fertig")
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
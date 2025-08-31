
# iCloud → AWS S3 Glacier Backup (Raspberry Pi, Docker)

Dieses Projekt sichert **iCloud Fotos** inkrementell nach **AWS S3** in eine Glacier‑Storage‑Klasse.
Es lädt jedes Asset einzeln (konstanter Plattenplatz) und läuft dauerhaft in einem Container.

## Was du bekommst
- Headless‑Sync mit 2FA‑Unterstützung (Cookie‑Session wird persistiert)
- Inkrementell (SQLite‑DB in `./state/db.sqlite3`)
- Speicherklassen wählbar: `DEEP_ARCHIVE`, `GLACIER`, `GLACIER_IR`
- S3‑Key‑Schema: `S3_PREFIX/YYYY/MM/{asset_id}_filename.ext`

## Voraussetzungen
- Raspberry Pi (64‑bit OS empfohlen) mit Docker & docker‑compose
- Ein bestehender S3‑Bucket (z. B. `mein-glacier-bucket`)
- IAM‑User/Role mit Rechten aus `iam-policy.example.json`

## Schnellstart
```bash
unzip icloud-glacier-backup.zip
cd icloud-glacier-backup
cp .env.example .env
# .env bearbeiten: iCloud/AWS Zugangsdaten eintragen
docker compose build
# Erster Start: einmalig 2FA-Code setzen
# echo "ICLOUD_2FA_CODE=123456" >> .env
docker compose up
# Wenn "Trusted Session" hergestellt, entferne ICLOUD_2FA_CODE wieder aus .env und starte neu:
# docker compose down ; $EDITOR .env ; docker compose up -d
```

## Hinweise
- Beim **Erstsync** werden viele Objekte übertragen. Das Script arbeitet **seriell** (ein Asset nach dem anderen),
  damit der lokale Speicherbedarf minimal bleibt.
- Du kannst `MAX_ASSETS_PER_RUN` setzen (z. B. `500`), wenn du die erste Runde in Etappen machen willst.
- Für **Server‑Side Encryption** setze `S3_SSE=AES256` oder KMS‑Varianten (siehe `docker-compose.yml`).
- Zeitplan: Standardmäßig alle 6h ein Lauf. Über `LOOP_INTERVAL_SECONDS` anpassen.
- Logs: `docker logs -f icloud-glacier-backup`

## Wiederherstellung
- Objekte liegen im S3‑Bucket unter `S3_PREFIX/YYYY/MM/...` in der gewählten Glacier‑Klasse.
- Je nach Klasse muss man vor dem Download ggf. eine **Restore‑Anfrage** stellen (außer `GLACIER_IR`).

## Troubleshooting
- **2FA**: Beim ersten Lauf `ICLOUD_2FA_CODE` setzen. Danach wird die Cookie‑Session im Volume `./cookies` benutzt.
- **Rate Limits**: Bei Apple oder AWS‑Fehlern wartet das Script bis zum nächsten Intervall.
- **Namens‑Kollisionen**: Der S3‑Key enthält immer die `asset_id`, damit es keine Überschneidungen gibt.

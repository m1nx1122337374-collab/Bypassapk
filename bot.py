import asyncio
import hashlib
import logging
import os
import tempfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from androguard.core.apk import APK
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
)
log = logging.getLogger("apk-analysis-bot")
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "19")) * 1024 * 1024
MAX_ZIP_ENTRIES = int(os.getenv("MAX_ZIP_ENTRIES", "100000"))
MAX_UNPACKED_BYTES = int(os.getenv("MAX_UNPACKED_MB", "512")) * 1024 * 1024

MENU = InlineKeyboardMarkup(
    [
        [InlineKeyboardButton("Analyze APK", callback_data="analyze")],
        [InlineKeyboardButton("Help", callback_data="help")],
        [InlineKeyboardButton("About", callback_data="about")],
    ]
)

SENSITIVE_PERMISSION_LABELS = {
    "android.permission.READ_SMS": "Read SMS messages",
    "android.permission.RECEIVE_SMS": "Receive SMS messages",
    "android.permission.SEND_SMS": "Send SMS messages",
    "android.permission.READ_CALL_LOG": "Read call history",
    "android.permission.WRITE_CALL_LOG": "Modify call history",
    "android.permission.RECORD_AUDIO": "Record audio",
    "android.permission.CAMERA": "Use camera",
    "android.permission.ACCESS_FINE_LOCATION": "Access precise location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Access location in background",
    "android.permission.READ_CONTACTS": "Read contacts",
    "android.permission.WRITE_CONTACTS": "Modify contacts",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Request package installation",
    "android.permission.SYSTEM_ALERT_WINDOW": "Draw over other apps",
    "android.permission.QUERY_ALL_PACKAGES": "Query installed packages",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility service capability",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Start after device boot",
}


def _safe_call(obj, method_name, default="Unavailable"):
    try:
        value = getattr(obj, method_name)()
        if value is None or value == "":
            return default
        return str(value)
    except Exception:
        return default


def analyze_apk(path: str) -> str:
    """Return a static metadata/permissions report; never modifies or rebuilds the APK."""
    apk_path = Path(path)
    if not zipfile.is_zipfile(apk_path):
        raise ValueError("The uploaded file is not a valid APK/ZIP archive.")

    with zipfile.ZipFile(apk_path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise ValueError("The APK contains too many archive entries to inspect safely.")
        expanded_size = sum(item.file_size for item in infos)
        if expanded_size > MAX_UNPACKED_BYTES:
            raise ValueError("The APK expands beyond the configured safe inspection limit.")
        names = [item.filename for item in infos]
        dex_files = sorted(name for name in names if name.rsplit("/", 1)[-1].startswith("classes") and name.endswith(".dex"))
        native_libs = sorted(name for name in names if name.startswith("lib/") and name.endswith(".so"))
        asset_count = sum(name.startswith("assets/") for name in names)
        has_manifest = "AndroidManifest.xml" in names

    if not has_manifest:
        raise ValueError("The archive does not contain AndroidManifest.xml and does not look like an APK.")

    digest = hashlib.sha256()
    with apk_path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)

    try:
        apk = APK(str(apk_path))
        package = _safe_call(apk, "get_package")
        app_name = _safe_call(apk, "get_app_name")
        version_name = _safe_call(apk, "get_androidversion_name")
        version_code = _safe_call(apk, "get_androidversion_code")
        min_sdk = _safe_call(apk, "get_min_sdk_version")
        target_sdk = _safe_call(apk, "get_target_sdk_version")
        permissions = sorted(set(apk.get_permissions() or []))
        activities = list(apk.get_activities() or [])
        services = list(apk.get_services() or [])
        receivers = list(apk.get_receivers() or [])
        providers = list(apk.get_providers() or [])
    except Exception as exc:
        log.info("APK manifest parsing failed: %s", type(exc).__name__)
        raise ValueError("Could not parse this APK manifest. The file may be malformed or unsupported.") from exc

    sensitive = [
        (permission, SENSITIVE_PERMISSION_LABELS[permission])
        for permission in permissions
        if permission in SENSITIVE_PERMISSION_LABELS
    ]

    lines = [
        "APK STATIC ANALYSIS REPORT",
        "Analysis is indicative only; this is not a malware verdict.",
        "",
        f"File: {apk_path.stat().st_size / (1024 * 1024):.2f} MB",
        f"SHA-256: {digest.hexdigest()}",
        f"Package: {package}",
        f"App name: {app_name}",
        f"Version: {version_name} (code {version_code})",
        f"SDK: min {min_sdk} / target {target_sdk}",
        f"DEX files: {len(dex_files)} | Native libraries: {len(native_libs)} | Assets: {asset_count}",
        "",
        f"Declared permissions ({len(permissions)}):",
    ]
    if permissions:
        lines.extend(f"- {permission}" for permission in permissions[:45])
        if len(permissions) > 45:
            lines.append(f"- ... and {len(permissions) - 45} more")
    else:
        lines.append("- None declared")

    lines += ["", f"Sensitive permission indicators ({len(sensitive)}):"]
    if sensitive:
        lines.extend(f"- {label} ({permission})" for permission, label in sensitive[:20])
        if len(sensitive) > 20:
            lines.append(f"- ... and {len(sensitive) - 20} more")
    else:
        lines.append("- None of the listed indicators found")

    lines += [
        "",
        "Manifest component counts:",
        f"- Activities: {len(activities)}",
        f"- Services: {len(services)}",
        f"- Receivers: {len(receivers)}",
        f"- Providers: {len(providers)}",
        "",
        "Privacy: the bot deletes its temporary local copy after analysis. Do not upload APKs unless you are authorized to analyze them.",
    ]
    return "\n".join(lines)[:3900]


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data["awaiting_apk"] = False
    await update.effective_message.reply_text(
        "Welcome to APK Static Analyzer.\n\n"
        "Upload an APK to receive a static report with package metadata, declared permissions, component counts, and selected risk indicators. "
        "This bot does not unpack protections, decrypt payloads, modify, rebuild, or sign APKs. Only analyze apps you own or are authorized to inspect.",
        reply_markup=MENU,
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(
        "How to use:\n"
        "1. Tap Analyze APK.\n"
        "2. Send one .apk file as a document.\n"
        "3. Wait for the static report.\n\n"
        f"Maximum upload: {MAX_UPLOAD_BYTES // (1024 * 1024)} MB. The report is informational, not a security certification."
    )


async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if query.data == "analyze":
        context.user_data["awaiting_apk"] = True
        await query.message.reply_text(
            f"Please send the APK as a document (maximum {MAX_UPLOAD_BYTES // (1024 * 1024)} MB). "
            "Only upload apps you own or have permission to analyze."
        )
    elif query.data == "help":
        await query.message.reply_text(
            "Tap Analyze APK, then send an .apk file as a document. The bot returns package details, permissions, component counts, and selected static indicators."
        )
    elif query.data == "about":
        await query.message.reply_text(
            "APK Static Analyzer provides basic, non-invasive triage. It does not bypass protections, extract/decrypt protected code, rebuild APKs, or run uploaded apps."
        )


async def receive_apk(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    document = message.document
    if not context.user_data.get("awaiting_apk"):
        await message.reply_text("Tap Analyze APK first, then send the APK as a document.", reply_markup=MENU)
        return
    name = (document.file_name or "").lower()
    if not name.endswith(".apk"):
        await message.reply_text("Please send an .apk file as a document.")
        return
    if document.file_size and document.file_size > MAX_UPLOAD_BYTES:
        await message.reply_text(f"This file exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.")
        return

    context.user_data["awaiting_apk"] = False
    status = await message.reply_text("APK received. Running static analysis…")
    try:
        with tempfile.TemporaryDirectory(prefix="apk-analysis-") as temp_dir:
            local_path = Path(temp_dir) / "upload.apk"
            telegram_file = await context.bot.get_file(document.file_id)
            await telegram_file.download_to_drive(custom_path=str(local_path))
            if local_path.stat().st_size > MAX_UPLOAD_BYTES:
                raise ValueError("The downloaded file exceeds the configured upload limit.")
            report = await asyncio.to_thread(analyze_apk, str(local_path))
        await status.edit_text(report)
    except ValueError as exc:
        await status.edit_text(f"Analysis could not be completed: {exc}")
    except Exception:
        log.exception("APK analysis failed")
        await status.edit_text("Analysis failed due to an internal error. Please try another APK later.")
    finally:
        context.user_data["awaiting_apk"] = False


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/health", "/healthz"):
            body = b"ok\n"
            self.send_response(200)
        else:
            body = b"not found\n"
            self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        log.info("health endpoint: " + fmt, *args)


def start_health_server() -> None:
    port = int(os.getenv("PORT", "10000"))
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    threading.Thread(target=server.serve_forever, name="health-server", daemon=True).start()
    log.info("Health endpoint listening on port %s", port)


def main() -> None:
    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        raise SystemExit("BOT_TOKEN is required. Set it as a Render environment secret.")
    start_health_server()
    application = Application.builder().token(token).concurrent_updates(False).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("cancel", start))
    application.add_handler(CallbackQueryHandler(menu_callback))
    application.add_handler(MessageHandler(filters.Document.ALL, receive_apk))
    log.info("Starting Telegram polling")
    application.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()

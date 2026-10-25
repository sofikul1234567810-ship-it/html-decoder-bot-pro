import os
import re
import json
import base64
import binascii
import html
import urllib.parse
import logging
import asyncio
import threading
from pathlib import Path
from io import BytesIO

from flask import Flask, jsonify
from telegram import Update
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    ContextTypes, filters
)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "5"))
MAX_FILE_SIZE = MAX_FILE_MB * 1024 * 1024
ALLOWED_EXTENSIONS = {".html", ".htm", ".js", ".mjs", ".cjs", ".txt", ".json", ".xml"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("html-decoder-bot")
logging.getLogger("httpx").setLevel(logging.WARNING)

web = Flask(__name__)

@web.get("/")
def home():
    return "HTML Decoder Bot is running."

@web.get("/health")
def health():
    return jsonify({"status": "ok"}), 200

def start_web():
    web.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")),
            debug=False, use_reloader=False)

def decode_common_layers(source: str):
    """Decode common text encodings only; never execute submitted JavaScript."""
    text = source
    notes = []

    # HTML entities
    unescaped = html.unescape(text)
    if unescaped != text:
        text = unescaped
        notes.append("HTML entities")

    # Percent encoding
    try:
        unquoted = urllib.parse.unquote(text)
        if unquoted != text:
            text = unquoted
            notes.append("URL percent-encoding")
    except Exception:
        pass

    # JavaScript unicode and hex escapes, preserving unrelated backslashes
    def unicode_repl(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
    changed = re.sub(r"\\u([0-9a-fA-F]{4})", unicode_repl, text)
    changed = re.sub(r"\\x([0-9a-fA-F]{2})", unicode_repl, changed)
    if changed != text:
        text = changed
        notes.append("JavaScript Unicode/hex escapes")

    # Decode quoted Base64 strings only when the result is valid readable text.
    # This does not execute eval(), Function(), or browser code.
    b64_pattern = re.compile(
        r"""(?P<q>['"])(?P<data>(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)(?P=q)"""
    )
    def b64_repl(m):
        data = m.group("data")
        try:
            raw = base64.b64decode(data, validate=True)
            decoded = raw.decode("utf-8")
            if decoded and sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded) / len(decoded) > 0.95:
                return m.group("q") + decoded + m.group("q")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
        return m.group(0)
    changed = b64_pattern.sub(b64_repl, text)
    if changed != text:
        text = changed
        notes.append("readable Base64 string literals")

    # Decode a file that is itself a plain Base64 payload.
    candidate = text.strip()
    if len(candidate) >= 8 and len(candidate) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", candidate):
        try:
            raw = base64.b64decode(candidate, validate=True)
            decoded = raw.decode("utf-8")
            if decoded and all(ch.isprintable() or ch in "\r\n\t" for ch in decoded):
                text = decoded
                notes.append("whole-file Base64")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass

    return text, notes

def basic_html_format(source: str) -> str:
    # Conservative line formatting; does not rewrite JS logic.
    source = re.sub(r">\s*<", ">\n<", source.strip())
    lines = source.splitlines()
    result = []
    depth = 0
    void_tags = {"area","base","br","col","embed","hr","img","input","link","meta","param","source","track","wbr"}
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if re.match(r"</", line):
            depth = max(0, depth - 1)
        result.append("    " * depth + line)
        m = re.match(r"<([a-zA-Z][\w:-]*)\b", line)
        if m and not line.startswith(("</", "<!", "<?")):
            tag = m.group(1).lower()
            if tag not in void_tags and not line.endswith("/>") and not re.search(r"</\s*" + re.escape(tag) + r"\s*>$", line, re.I):
                depth += 1
    return "\n".join(result)

def analyze(source: str, filename: str, notes=None) -> str:
    extension = Path(filename).suffix.lower() or "unknown"
    indicators = {
        "eval()": r"\beval\s*\(",
        "Function constructor": r"\bnew\s+Function\b|\bFunction\s*\(",
        "Base64 decoding": r"\batob\s*\(",
        "URL decoding": r"\bdecodeURIComponent\s*\(|\bunescape\s*\(",
        "dynamic code patterns": r"fromCharCode|String\.raw",
        "anti-debugging indicators": r"debugger\s*;|toString\s*\(\s*\).*debugger",
    }
    lines = [
        "HTML/JS STATIC ANALYSIS",
        f"File: {filename}",
        f"Type: {extension}",
        f"Size: {len(source.encode('utf-8', errors='replace'))} bytes",
        f"Lines: {len(source.splitlines())}",
        "",
        "Pattern counts (indicators only; not proof of malware):"
    ]
    for label, pattern in indicators.items():
        lines.append(f"- {label}: {len(re.findall(pattern, source, re.I))}")
    if notes:
        lines += ["", "Decoding steps applied: " + ", ".join(notes)]
    lines += [
        "",
        "Important: this bot never executes uploaded code. Complex encrypted payloads, custom ciphers,",
        "runtime-generated code, and anti-analysis protections may not be reversible automatically."
    ]
    return "\n".join(lines)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "🤖 HTML Decoder Bot\n\n"
        "Send an HTML/JS/TXT/JSON/XML file, or choose a command first:\n"
        "/decode — decode common text encodings\n"
        "/beautify — basic HTML formatting\n"
        "/analyze — static analysis report\n"
        "/help — show help\n\n"
        f"Maximum file size: {MAX_FILE_MB} MB\n"
        "Note: complex encryption/obfuscation may need manual analysis."
    )

async def set_mode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mode = update.effective_message.text.split()[0].lower().lstrip("/")
    context.user_data["mode"] = mode
    await update.effective_message.reply_text(
        f"Mode: {mode.upper()}.\nNow upload the file."
    )

async def process_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    doc = message.document
    if not doc:
        return
    filename = Path(doc.file_name or "upload.txt").name
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        await message.reply_text("Unsupported file. Send HTML, HTM, JS, TXT, JSON, or XML.")
        return
    if doc.file_size and doc.file_size > MAX_FILE_SIZE:
        await message.reply_text(f"File is too large. Limit: {MAX_FILE_MB} MB.")
        return

    status = await message.reply_text("⏳ Reading and processing safely...")
    try:
        tgfile = await context.bot.get_file(doc.file_id)
        data = await tgfile.download_as_bytearray()
        if len(data) > MAX_FILE_SIZE:
            await status.edit_text(f"File is too large. Limit: {MAX_FILE_MB} MB.")
            return
        source = bytes(data).decode("utf-8-sig", errors="replace")
        mode = context.user_data.pop("mode", "decode")

        if mode == "analyze":
            report = analyze(source, filename)
            await status.edit_text(report[:4000])
            return
        if mode == "beautify":
            output = basic_html_format(source) if ext in {".html", ".htm", ".xml"} else source
            suffix = "_beautified"
            caption = "Basic formatting complete."
        else:
            output, notes = decode_common_layers(source)
            suffix = "_decoded"
            caption = "Common decoding finished. Steps: " + (", ".join(notes) if notes else "No common encoding detected")
            if output == source:
                caption += ". This file may use custom encryption/obfuscation."
        out_ext = ext or ".txt"
        out_name = f"{Path(filename).stem}{suffix}{out_ext}"
        encoded = output.encode("utf-8")
        if len(encoded) > MAX_FILE_SIZE:
            await status.edit_text("Output exceeds the configured size limit.")
            return
        await status.delete()
        buf = BytesIO(encoded)
        buf.name = out_name
        await message.reply_document(document=buf, filename=out_name, caption=caption[:900])
    except Exception:
        logger.exception("Processing error")
        try:
            await status.edit_text("Could not process this file. Check Render logs.")
        except Exception:
            pass

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "Please upload a supported file. Use /decode, /beautify, or /analyze first."
    )

async def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN is missing in Render Environment Variables.")
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
    app.add_handler(CommandHandler("decode", set_mode))
    app.add_handler(CommandHandler("beautify", set_mode))
    app.add_handler(CommandHandler("analyze", set_mode))
    app.add_handler(MessageHandler(filters.Document.ALL, process_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    threading.Thread(target=start_web, daemon=True).start()
    await app.initialize()
    await app.start()
    if app.updater is None:
        raise RuntimeError("Telegram polling is unavailable.")
    await app.updater.start_polling(drop_pending_updates=True)
    logger.info("Bot started.")
    try:
        await asyncio.Event().wait()
    finally:
        await app.updater.stop()
        await app.stop()
        await app.shutdown()

if __name__ == "__main__":
    asyncio.run(main())

# HTML Decoder Telegram Bot

## GitHub files
Upload these files to the repository root:
- `app.py`
- `requirements.txt`
- `render.yaml`

## Render setup
- Build Command: `pip install -r requirements.txt`
- Start Command: `python app.py`
- Add Environment Variable `BOT_TOKEN` with your Telegram bot token.

## Commands
- `/decode` — common encodings (HTML entities, percent encoding, JS unicode/hex escapes, readable Base64 strings)
- `/beautify` — conservative HTML/XML formatting
- `/analyze` — static pattern report

The bot never executes uploaded code. It does not promise to reverse custom encryption, proprietary obfuscation, or all anti-debugging protections.

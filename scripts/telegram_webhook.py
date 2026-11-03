#!/usr/bin/env python3
"""
Points Telegram at redhand-core's webhook (or shows / removes it). Standard library only.

  python3 scripts/telegram_webhook.py set  --project <gcp-project> --core-url https://<core>.run.app
  python3 scripts/telegram_webhook.py info --project <gcp-project>
  python3 scripts/telegram_webhook.py delete --project <gcp-project>

The bot token and the webhook secret are read from Google Secret Manager through your own
`gcloud` login (the names `deploy.sh telegram` created), or from the environment variables
TELEGRAM_BOT_TOKEN and TELEGRAM_WEBHOOK_SECRET. They are sent to Telegram only and never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any

SECRET_TOKEN = "redhand-telegram-bot-token"
SECRET_WEBHOOK = "redhand-telegram-webhook-secret"
WEBHOOK_PATH = "/v1/telegram/webhook"


def secret_value(env_name: str, secret_name: str, project: str | None) -> str:
    from_env = os.environ.get(env_name)
    if from_env:
        return from_env.strip()
    if not project:
        sys.exit(f"Give --project (to read {secret_name} from Secret Manager) or set {env_name}.")
    result = subprocess.run(  # noqa: S603  fixed argument list, no shell
        ["gcloud", "secrets", "versions", "access", "latest", f"--secret={secret_name}", f"--project={project}"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        sys.exit(f"Could not read secret {secret_name}. Run 'deploy/cloudrun/deploy.sh telegram' first.")
    return result.stdout.strip()


def telegram_call(token: str, method: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=json.dumps(payload or {}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        body = error.read()
    except (urllib.error.URLError, TimeoutError) as error:
        # The exception text can contain the request URL, which contains the token: say only the class.
        sys.exit(f"Could not reach Telegram ({type(error).__name__}).")
    parsed: dict[str, Any] = json.loads(body)
    return parsed


def show_info(token: str) -> None:
    info = telegram_call(token, "getWebhookInfo").get("result", {})
    print(f"webhook url      : {info.get('url') or '(none)'}")
    print(f"pending updates  : {info.get('pending_update_count', 0)}")
    if info.get("last_error_message"):
        print(f"last error       : {info['last_error_message']}")
    me = telegram_call(token, "getMe").get("result", {})
    print(f"bot              : @{me.get('username', '?')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["set", "info", "delete"])
    parser.add_argument("--project", help="Google Cloud project that holds the secrets")
    parser.add_argument("--core-url", help="redhand-core's public https URL (for 'set')")
    args = parser.parse_args()

    token = secret_value("TELEGRAM_BOT_TOKEN", SECRET_TOKEN, args.project)
    if args.action == "info":
        show_info(token)
        return 0
    if args.action == "delete":
        result = telegram_call(token, "deleteWebhook", {"drop_pending_updates": True})
        print("webhook removed" if result.get("ok") else f"failed: {result.get('description')}")
        return 0 if result.get("ok") else 1

    if not args.core_url or not args.core_url.startswith("https://"):
        sys.exit("Give --core-url https://<your core service>.run.app (Telegram only accepts https).")
    secret = secret_value("TELEGRAM_WEBHOOK_SECRET", SECRET_WEBHOOK, args.project)
    result = telegram_call(token, "setWebhook", {
        "url": args.core_url.rstrip("/") + WEBHOOK_PATH,
        "secret_token": secret,
        "allowed_updates": ["message"],
        "drop_pending_updates": True,
        "max_connections": 5,
    })
    if not result.get("ok"):
        print(f"failed: {result.get('description')}")
        return 1
    print("webhook set")
    show_info(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())

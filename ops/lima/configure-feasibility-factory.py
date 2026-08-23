#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path

FACTORY_ROOT = Path("/home/shadow/.factory")
SETTINGS_PATH = FACTORY_ROOT / "settings.json"
TRUSTED_ROOT = "/home/shadow/workspace"
EXPECTED_PLUGIN = {"shadow-mission@shadow-feasibility-local": True}
EXPECTED_MARKETPLACE = {
    "shadow-feasibility-local": {
        "source": {
            "source": "local",
            "path": "/home/shadow/input/shadow-feasibility-local",
        }
    }
}
ALLOWED_INITIAL_KEYS = {
    "enabledPlugins",
    "extraKnownMarketplaces",
    "logoAnimation",
    "trustedFolders",
}


def main() -> None:
    settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    if not isinstance(settings, dict) or not set(settings).issubset(ALLOWED_INITIAL_KEYS):
        raise SystemExit("Factory settings contain an unapproved surface")
    if settings.get("enabledPlugins") != EXPECTED_PLUGIN:
        raise SystemExit("Factory plugin activation differs from the approved set")
    if settings.get("extraKnownMarketplaces") != EXPECTED_MARKETPLACE:
        raise SystemExit("Factory marketplace differs from the approved set")
    trusted = settings.get("trustedFolders", {})
    if not isinstance(trusted, dict) or not set(trusted).issubset(
        {"/home/shadow", TRUSTED_ROOT}
    ):
        raise SystemExit("Factory trusted-folder state differs from the approved set")

    settings = {
        "cloudSessionSync": False,
        "enabledPlugins": EXPECTED_PLUGIN,
        "extraKnownMarketplaces": EXPECTED_MARKETPLACE,
        "hooksDisabled": False,
        "logoAnimation": "off",
        "sandbox": {
            "enabled": True,
            "mode": "whole-process",
            "filesystem": {
                "denyRead": [
                    "/home/shadow/credential",
                    "/home/shadow/input",
                    "/home/shadow/private",
                    "/home/shadow/protected",
                ]
            },
            "network": {"allowedDomains": ["127.0.0.1"]},
        },
        "trustedFolders": {
            TRUSTED_ROOT: {
                "trustedAt": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            }
        },
    }
    temporary = SETTINGS_PATH.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(settings, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, SETTINGS_PATH)


if __name__ == "__main__":
    main()

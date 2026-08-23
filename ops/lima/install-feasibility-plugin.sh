#!/bin/sh
set -eu

umask 077
DROID=/home/shadow/bin/droid-pinned
MARKETPLACE=/home/shadow/input/shadow-feasibility-local

if [ "$(id -un)" != 'shadowgate' ]; then
    echo 'plugin installation must run as shadowgate' >&2
    exit 126
fi
if [ ! -x "$DROID" ] || [ ! -f "$MARKETPLACE/.factory-plugin/marketplace.json" ]; then
    echo 'pinned Droid or plugin source is unavailable' >&2
    exit 126
fi

"$DROID" plugin marketplace add "$MARKETPLACE"
"$DROID" plugin install shadow-mission@shadow-feasibility-local --scope user
"$DROID" plugin list --scope user

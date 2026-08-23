#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo 'guest prerequisite installation must run as root' >&2
    exit 126
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    bubblewrap=0.9.0-1ubuntu0.1 \
    python3.12-venv=3.12.3-1ubuntu0.15 \
    socat=1.8.0.0-4ubuntu0.1

dpkg-query -W -f='${Package}=${Version}\n' \
    bubblewrap python3.12-venv socat

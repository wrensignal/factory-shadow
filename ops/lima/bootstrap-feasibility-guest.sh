#!/bin/sh
set -eu

umask 077
DROID_TARBALL_URL='https://registry.npmjs.org/@factory/cli-linux-arm64/-/cli-linux-arm64-0.197.0.tgz'
DROID_TARBALL_SHA512='7fd5af5edf82aa07441eab15e254026d01c17159d3ccf74230e2a883cc073dbc2f404a79fc2814f6622814841cd2f82d686d441419111424398487f2e4daacc5'
DROID_BINARY_SHA256='9bf6a5b667ed231d75c6aef720c02d54b042d45d1da6551832e6ae4376d667f9'

if [ "$(id -un)" != 'shadowgate' ]; then
    echo 'guest bootstrap must run as shadowgate' >&2
    exit 126
fi

archive=$(mktemp /tmp/shadow-droid.XXXXXX.tgz)
staging=$(mktemp -d /tmp/shadow-droid.XXXXXX)
cleanup() {
    rm -f "$archive"
    rm -rf "$staging"
}
trap cleanup EXIT HUP INT TERM

curl -fsSL "$DROID_TARBALL_URL" -o "$archive"
printf '%s  %s\n' "$DROID_TARBALL_SHA512" "$archive" | sha512sum -c -
tar -xzf "$archive" -C "$staging" package/bin/droid
printf '%s  %s\n' "$DROID_BINARY_SHA256" "$staging/package/bin/droid" | sha256sum -c -

install -d -m 0700 \
    /home/shadow/bin \
    /home/shadow/credential \
    /home/shadow/private \
    /home/shadow/output \
    /home/shadow/workspace
install -m 0700 "$staging/package/bin/droid" /home/shadow/bin/droid
install -m 0700 /home/shadow/input/droid-pinned /home/shadow/bin/droid-pinned
install -m 0700 /home/shadow/input/droid-authenticated /home/shadow/bin/droid-authenticated
python3 -m venv /home/shadow/venv
/home/shadow/venv/bin/python -m pip install \
    --require-hashes \
    --only-binary=:all: \
    -r /home/shadow/input/requirements-feasibility.txt
cat > /home/shadow/venv/bin/shadow-feasibility <<'EOF'
#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=/home/shadow/input/src
exec /home/shadow/venv/bin/python -m shadow_mission.feasibility "$@"
EOF
chmod 0700 /home/shadow/venv/bin/shadow-feasibility

/home/shadow/bin/droid-pinned --version
printf '%s\n' 'pinned guest bootstrap complete'

#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo 'guest privilege hardening must run as root' >&2
    exit 126
fi
if ! id shadowgate >/dev/null 2>&1; then
    echo 'shadowgate guest user is unavailable' >&2
    exit 126
fi

install -d -o root -g root -m 0700 /home/shadow/protected
printf '%s\n' 'shadow-guest-protected-canary' > /home/shadow/protected/read-canary
chown root:root /home/shadow/protected/read-canary
chmod 0600 /home/shadow/protected/read-canary
install -d -o shadowgate -g shadowgate -m 0700 /home/shadow/credential
printf '%s\n' 'shadow-sandbox-input-canary' > /home/shadow/input/sandbox-input-canary.txt
chown shadowgate:shadowgate /home/shadow/input/sandbox-input-canary.txt
chmod 0400 /home/shadow/input/sandbox-input-canary.txt
printf '%s\n' 'shadow-sandbox-credential-canary' > /home/shadow/credential/sandbox-credential-canary.txt
chown shadowgate:shadowgate /home/shadow/credential/sandbox-credential-canary.txt
chmod 0400 /home/shadow/credential/sandbox-credential-canary.txt


for path in \
    /home/shadow/input \
    /home/shadow/bin/droid \
    /home/shadow/bin/droid-pinned \
    /home/shadow/bin/droid-authenticated \
    /home/shadow/venv
do
    if [ ! -e "$path" ] || [ -L "$path" ]; then
        echo "guest sealed path is unavailable: $path" >&2
        exit 126
    fi
    chown -R root:root "$path"
    chmod -R u=rwX,go=rX "$path"
done

cloud_sudoers=/etc/sudoers.d/90-cloud-init-users
if [ -e "$cloud_sudoers" ]; then
    if [ -L "$cloud_sudoers" ] || [ ! -f "$cloud_sudoers" ]; then
        echo 'cloud-init sudoers state is invalid' >&2
        exit 126
    fi
    if ! awk '
        /^[[:space:]]*($|#)/ { next }
        $1 == "shadowgate" { next }
        { exit 1 }
    ' "$cloud_sudoers"; then
        echo 'cloud-init sudoers contains an unexpected grant' >&2
        exit 126
    fi
    rm -f "$cloud_sudoers"
fi

if id -nG shadowgate | tr ' ' '\n' | awk '$0 == "sudo" { found = 1 } END { exit !found }'; then
    gpasswd -d shadowgate sudo >/dev/null
fi

if awk '
    /^[[:space:]]*($|#)/ { next }
    $1 == "shadowgate" { found = 1 }
    END { exit !found }
' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    echo 'shadowgate retains a direct sudoers grant' >&2
    exit 126
fi
visudo -c >/dev/null
printf '%s\n' 'shadowgate sudo rights removed'

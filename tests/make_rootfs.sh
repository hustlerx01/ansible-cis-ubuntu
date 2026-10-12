#!/usr/bin/env bash
# Build a fake "stock Ubuntu" rootfs with typical insecure defaults.
set -e; R="$1"; rm -rf "$R"; mkdir -p "$R/etc/ssh" "$R/etc/sysctl.d"
cat > "$R/etc/ssh/sshd_config" <<'X'
#PermitRootLogin prohibit-password
PasswordAuthentication yes
X11Forwarding yes
KbdInteractiveAuthentication no
X
chmod 644 "$R/etc/ssh/sshd_config"
printf 'PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nUMASK\t022\n' > "$R/etc/login.defs"
printf 'root:x:0:0:root:/root:/bin/bash\n' > "$R/etc/passwd"; chmod 644 "$R/etc/passwd"
printf 'root:*:19000:0:99999:7:::\n' > "$R/etc/shadow"; chmod 666 "$R/etc/shadow"
printf '#net.ipv4.ip_forward=1\n' > "$R/etc/sysctl.conf"
printf 'Ubuntu 24.04 LTS \\n \\l\n' > "$R/etc/issue.net"

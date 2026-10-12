# Test container: real Ubuntu 24.04 userland, role applied to "/" inside it (live mode, minus sysctl reload).
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ansible-core openssh-server python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
ENV ANSIBLE_ROLES_PATH=/src/roles
# sysctl --system can't run unprivileged in a container, so skip live reloads but harden real /etc
RUN ansible-playbook -i localhost, -c local tests/site_test.yml -e cis_ubuntu_apply_live=false \
 && mkdir -p /run/sshd && sshd -t && python3 audit/cis_audit.py /
CMD ["sh", "-c", "sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|maxauthtries'; python3 audit/cis_audit.py /"]

# Interview talking points: ansible-cis-ubuntu
1. **Idempotence is the test.** The second run reports changed=0. If it didn't, every run would restart services and hide real drift.
2. **Independent verification.** The audit script re-derives compliance from files and doesn't import role vars. Tests that only re-read your own inputs prove nothing.
3. **Why drop-ins.** `sshd_config.d/60-cis.conf` plus `Include` at the top: sshd uses the *first* value it sees, so including at the top makes our values win without fighting the distro's file during package upgrades.
4. **Testing without root.** `cis_ubuntu_root` lets CI converge into a temp dir in 6 s. Molecule with a systemd container covers live behaviour. These are layered tests: fast first, realistic second.
5. **Lockout risk.** I'd roll out with `serial: 10%`, `sshd -t` validation, and a break-glass console. Hardening that takes prod down is a failure.
6. **Mapping to compliance.** Each task is tagged with a CIS ID so auditors can trace a control to code. It's the same idea as compliance-as-code tools (OpenSCAP, InSpec).
7. **Lint as a gate.** ansible-lint's production profile caught naming and variable-prefix issues; CI fails on them.

"""Independent compliance checker (does not reuse role vars) -> JSON score.
Usage: cis_audit.py <rootfs> [--json out.json]"""
import json, re, stat, sys
from pathlib import Path

def read(root, p):
    f = Path(root, p.lstrip("/"))
    return f.read_text() if f.exists() else ""

def sshd_effective(root):
    txt = read(root, "etc/ssh/sshd_config")
    for d in sorted(Path(root, "etc/ssh/sshd_config.d").glob("*.conf")) if Path(root, "etc/ssh/sshd_config.d").exists() else []:
        txt = d.read_text() + "\n" + txt   # sshd: first value wins; drop-ins included at top
    cfg = {}
    for line in txt.splitlines():
        m = re.match(r"^\s*(\w+)\s+(.+?)\s*$", line)
        if m and not line.strip().startswith("#"):
            cfg.setdefault(m.group(1).lower(), m.group(2).lower())
    return cfg

def sysctl_all(root):
    vals = {}
    d = Path(root, "etc/sysctl.d")
    for f in ([Path(root, "etc/sysctl.conf")] + sorted(d.glob("*.conf")) if d.exists() else [Path(root, "etc/sysctl.conf")]):
        if f.exists():
            for line in f.read_text().splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, v = [x.strip() for x in line.split("=", 1)]; vals[k] = v
    return vals

def mode(root, p):
    f = Path(root, p)
    return stat.S_IMODE(f.stat().st_mode) if f.exists() else None

def checks(root):
    s, sc = sshd_effective(root), sysctl_all(root)
    modp = "".join(f.read_text() for f in Path(root, "etc/modprobe.d").glob("*.conf")) if Path(root, "etc/modprobe.d").exists() else ""
    ld = read(root, "etc/login.defs")
    pmax = re.search(r"^PASS_MAX_DAYS\s+(\d+)", ld, re.M)
    out = {
        "1.1.1.1 cramfs disabled": "install cramfs /bin/false" in modp,
        "1.1.1.x usb-storage disabled": "install usb-storage /bin/false" in modp,
        "1.5.3 ASLR=2": sc.get("kernel.randomize_va_space") == "2",
        "1.5.x suid_dumpable=0": sc.get("fs.suid_dumpable") == "0",
        "3.2.1 ip_forward=0": sc.get("net.ipv4.ip_forward") == "0",
        "3.3.1 source routing off": sc.get("net.ipv4.conf.all.accept_source_route") == "0",
        "3.3.2 ICMP redirects off": sc.get("net.ipv4.conf.all.accept_redirects") == "0",
        "3.3.8 tcp_syncookies=1": sc.get("net.ipv4.tcp_syncookies") == "1",
        "5.2.1 sshd_config 0600": mode(root, "etc/ssh/sshd_config") in (0o600,),
        "5.2.7 PermitRootLogin no": s.get("permitrootlogin") == "no",
        "5.2.x PasswordAuthentication no": s.get("passwordauthentication") == "no",
        "5.2.9 PermitEmptyPasswords no": s.get("permitemptypasswords") == "no",
        "5.2.12 X11Forwarding no": s.get("x11forwarding") == "no",
        "5.2.18 MaxAuthTries<=4": s.get("maxauthtries", "6").isdigit() and int(s.get("maxauthtries", "6")) <= 4,
        "5.5.1.2 PASS_MAX_DAYS<=365": bool(pmax) and int(pmax.group(1)) <= 365,
        "1.7.x /etc/issue.net banner": "authorized" in read(root, "etc/issue.net").lower(),
        "6.1.x /etc/shadow <=0640": (mode(root, "etc/shadow") or 0o777) & 0o137 == 0,
        "4.1.3 audit identity rules": "-k identity" in "".join(f.read_text() for f in Path(root, "etc/audit/rules.d").glob("*.rules")) if Path(root, "etc/audit/rules.d").exists() else False,
    }
    return out

if __name__ == "__main__":
    root = sys.argv[1]; res = checks(root)
    passed = sum(res.values())
    for k, v in res.items(): print(f"{'PASS' if v else 'FAIL'}  {k}")
    print(f"SCORE {passed}/{len(res)}")
    if "--json" in sys.argv: Path(sys.argv[sys.argv.index("--json") + 1]).write_text(json.dumps({"passed": passed, "total": len(res), "checks": res}, indent=1))
    sys.exit(0 if passed == len(res) else 2)

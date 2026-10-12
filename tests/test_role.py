"""Converge the role against a throwaway rootfs (no root, no Docker), check idempotence + audit score."""
import json, os, re, shutil, subprocess, sys
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
PLAY = shutil.which("ansible-playbook") or str(Path(sys.executable).parent / "ansible-playbook")

def run_play(rootfs):
    env = dict(os.environ, ANSIBLE_ROLES_PATH=str(ROOT / "roles"), ANSIBLE_NOCOLOR="1", ANSIBLE_LOCALHOST_WARNING="False", ANSIBLE_INVENTORY_UNPARSED_WARNING="False")
    p = subprocess.run([PLAY, "-i", "localhost,", str(ROOT / "tests/site_test.yml"), "-e", f"cis_ubuntu_root={rootfs}"], capture_output=True, text=True, env=env)
    assert p.returncode == 0, p.stdout + p.stderr
    return p.stdout

def audit(rootfs):
    p = subprocess.run([sys.executable, str(ROOT / "audit/cis_audit.py"), str(rootfs)], capture_output=True, text=True)
    return p.stdout, int(re.search(r"SCORE (\d+)/", p.stdout).group(1))

@pytest.fixture
def rootfs(tmp_path):
    r = tmp_path / "rootfs"; subprocess.run(["bash", str(ROOT / "tests/make_rootfs.sh"), str(r)], check=True); return r

def test_baseline_is_noncompliant(rootfs):
    out, score = audit(rootfs); assert score <= 2, out

def test_converge_full_compliance_and_idempotent(rootfs):
    first = run_play(rootfs)
    out, score = audit(rootfs)
    assert "FAIL" not in out, out
    second = run_play(rootfs)
    assert re.search(r"changed=0\s", second), second

def test_existing_insecure_value_overridden(rootfs):
    run_play(rootfs)
    assert "PASS_MAX_DAYS\t365" in (rootfs / "etc/login.defs").read_text()
    assert oct((rootfs / "etc/shadow").stat().st_mode & 0o777) == "0o640"

"""Linux user custody across a vendor auto-update: trusted vendor roots.

A copy of the test interpreter under ``<root>/versions/<version>`` plays the
vendor. The profile pins version 1.0.0; the "updated" vendor runs 2.0.0 from a
different path. Without a trusted root that is no vendor ancestor at all (the
pre-change behaviour); with the ``versions`` root it is, as long as custody of
the file and of every directory down to it is owner-only.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import pytest

from integrity_client_memory import linux_user_native as native
from integrity_client_memory import native_install as install

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc custody primitive")

READER = r"""
import json, sys
from integrity_client_memory import linux_user_native as n
mode, args = sys.argv[1], sys.argv[2:]
try:
    if mode == "ancestor":
        exe, pin, roots = args[0], args[1], json.loads(args[2])
        print(json.dumps(list(n.find_vendor_image_ancestor(exe, pin, trusted_roots=roots))))
    else:
        root, thread, exe, pin, roots = args[0], args[1], args[2], args[3], json.loads(args[4])
        print(json.dumps(n.verified_head(root, thread, exe, pin, roots)))
except n.LinuxNativeError as error:
    print(json.dumps({"error": str(error)}))
"""
# The vendor copy runs the reader as its own child, so it is the nearest ancestor.
VENDOR = r"""
import subprocess, sys
done = subprocess.run([sys.executable, "-c", sys.argv[1], *sys.argv[2:]], capture_output=True, text=True)
sys.stdout.write(done.stdout); sys.stderr.write(done.stderr); raise SystemExit(done.returncode)
"""


def vendor_tree(tmp_path):
    versions = tmp_path / "share" / "claude" / "versions"
    versions.mkdir(parents=True)
    for path in (tmp_path / "share", tmp_path / "share" / "claude", versions):
        path.chmod(0o755)
    source = os.path.realpath(sys.executable)
    for version in ("1.0.0", "2.0.0"):
        shutil.copy2(source, versions / version)
        (versions / version).chmod(0o755)
    return versions


def run_as_vendor(vendor, *args):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    done = subprocess.run([str(vendor), "-c", VENDOR, READER, *args], capture_output=True, text=True,
                          env=env, timeout=120)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_updated_vendor_is_no_ancestor_without_a_root_and_trusted_with_one(tmp_path):
    versions = vendor_tree(tmp_path)
    pinned, pin = native.pin_executable(str(versions / "1.0.0"))
    updated = versions / "2.0.0"
    assert run_as_vendor(updated, "ancestor", pinned, pin, "[]") == {"error": "linux_native_vendor_ancestor_missing"}
    pid, _, digest = run_as_vendor(updated, "ancestor", pinned, pin, json.dumps([str(versions)]))
    assert isinstance(pid, int) and digest == native.file_digest(updated)


def test_group_writable_chain_or_image_outside_the_root_is_refused(tmp_path):
    versions = vendor_tree(tmp_path)
    pinned, pin = native.pin_executable(str(versions / "1.0.0"))
    roots = json.dumps([str(versions)])
    versions.chmod(0o775)
    assert run_as_vendor(versions / "2.0.0", "ancestor", pinned, pin, roots) == {
        "error": "linux_native_vendor_ancestor_missing"}
    versions.chmod(0o755)
    (versions / "2.0.0").chmod(0o775)
    assert run_as_vendor(versions / "2.0.0", "ancestor", pinned, pin, roots) == {
        "error": "linux_native_vendor_ancestor_missing"}
    outside = tmp_path / "elsewhere"
    outside.mkdir(mode=0o755)
    shutil.copy2(os.path.realpath(sys.executable), outside / "claude")
    (outside / "claude").chmod(0o755)
    assert run_as_vendor(outside / "claude", "ancestor", pinned, pin, roots) == {
        "error": "linux_native_vendor_ancestor_missing"}


def test_head_is_bound_to_the_image_that_published_it(tmp_path):
    versions = vendor_tree(tmp_path)
    pinned, pin = native.pin_executable(str(versions / "1.0.0"))
    updated = versions / "2.0.0"
    roots = json.dumps([str(versions)])
    pid, birth, digest = run_as_vendor(updated, "ancestor", pinned, pin, roots)
    heads = tmp_path / "heads"
    native.private_directory(heads)
    thread, turn = str(uuid.uuid4()), str(uuid.uuid4())
    # A head published by the vendor process itself: the reader runs as its child.
    publisher = (
        "import os,sys,json,uuid\n"
        "from integrity_client_memory import linux_user_native as n\n"
        "pid,birth,image=n.find_vendor_image_ancestor(sys.argv[3],sys.argv[4],trusted_roots=json.loads(sys.argv[5]))\n"
        "n.publish_head(sys.argv[1],thread_id=sys.argv[2],turn_id=sys.argv[6],status='inProgress',"
        "pid=pid,birth=birth,executable_sha256=image)\n"
        "print(json.dumps(n.verified_head(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],json.loads(sys.argv[5]))))\n")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    done = subprocess.run([str(updated), "-c", VENDOR, publisher, str(heads), thread, pinned, pin, roots, turn],
                          capture_output=True, text=True, env=env, timeout=120)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {"id": turn, "status": "inProgress"}
    recorded = native.read_head(heads, thread)["native_executable_sha256"]
    assert recorded == digest
    # Without the root, the same head is no longer accepted.
    done = subprocess.run([str(updated), "-c", VENDOR, READER, "head", str(heads), thread, pinned, pin, "[]"],
                          capture_output=True, text=True, env=env, timeout=120)
    assert json.loads(done.stdout) == {"error": "linux_native_vendor_ancestor_missing"}


def test_install_trusts_the_versions_directory_by_default(tmp_path):
    versions = vendor_tree(tmp_path)
    binding = install.linux_native_binding("claude", {"claude_executable": str(versions / "1.0.0")})
    assert binding["trusted_roots"] == [str(versions)]
    explicit = install.linux_native_binding("claude", {"claude_executable": str(versions / "1.0.0"),
                                                       "claude_executable_roots": []})
    assert explicit["trusted_roots"] == []
    versions.chmod(0o777)
    with pytest.raises(ValueError, match="trusted root rejected"):
        install.linux_native_binding("claude", {"claude_executable": str(versions / "1.0.0")})

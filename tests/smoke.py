"""Exercise the built Linux CLI without depending on external connectivity."""
import json
import pathlib
import stat
import subprocess
import sys
import tempfile


binary = pathlib.Path(sys.argv[1]).resolve()


def run(*args, ok=True):
    result = subprocess.run([binary, *args], text=True, capture_output=True, timeout=12)
    assert (result.returncode == 0) == ok, result
    return result


assert run("--version").stdout.strip() == "netautopsy 0.1.0"
run("diagnose", "--host", "-invalid.test", ok=False)
run("diagnose", "--target", "example.com", ok=False)
run("diagnose", "--timeout-ms", "0", ok=False)
run("diagnose", "--json", "--output", "unused.json", ok=False)

with tempfile.TemporaryDirectory() as tmp:
    path = pathlib.Path(tmp) / "capture.json"
    args = ["diagnose", "--passive", "--target", "127.0.0.1"]
    result = run(*args, "--output", str(path))
    payload = path.read_bytes()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    report = json.loads(payload)
    assert report["schema"] == 1
    assert [event["state"] for event in report["evidence"][3:]] == ["skipped"] * 3
    assert "dev=lo" in report["evidence"][0]["detail"]
    assert run("inspect", str(path)).stdout == result.stdout
    run(*args, "--output", str(path), ok=False)
    assert path.read_bytes() == payload
    report["schema"] = 99
    path.write_text(json.dumps(report))
    run("inspect", str(path), ok=False)
    path.write_bytes(b" " * (1024 * 1024 + 1))
    run("inspect", str(path), ok=False)

active = json.loads(run("diagnose", "--target", "127.0.0.1", "--host", "localhost",
                        "--timeout-ms", "500", "--json").stdout)
assert active["evidence"][0]["state"] == "pass"
assert active["evidence"][5]["state"] == "pass"
assert active["evidence"][4]["state"] in {"pass", "fail"}
print("PASS CLI, passive mode, active loopback, private export, offline replay and invalid inputs")

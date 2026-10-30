"""Stand-in for the subfinder binary used by tests.

Behaviour is chosen by FAKE_SUBFINDER_MODE: "fixture" prints subfinder.jsonl,
"sleep" hangs, "flood" prints without end, "fail" exits non-zero.
The received argv is written to FAKE_SUBFINDER_ARGV when set.
"""
import json
import os
import sys
import time
from pathlib import Path

if os.environ.get("FAKE_SUBFINDER_ARGV"):
    Path(os.environ["FAKE_SUBFINDER_ARGV"]).write_text(json.dumps(sys.argv[1:]))
mode = os.environ.get("FAKE_SUBFINDER_MODE", "fixture")
if mode == "fixture":
    sys.stdout.write((Path(__file__).parent / "subfinder.jsonl").read_text())
elif mode == "sleep":
    time.sleep(60)
elif mode == "flood":
    line = json.dumps({"host": "x.example.com", "source": "flood"}) + "\n"
    while True:
        sys.stdout.write(line * 1000)
        sys.stdout.flush()
elif mode == "fail":
    sys.stderr.write("rate limited\n")
    sys.exit(2)

#!/usr/bin/python3 -I
# SPDX-License-Identifier: LGPL-3.0-or-later
"""own-procs: list or stop processes of THIS account by exact PID, after checking uid and command line.

  own-procs.py list
  own-procs.py stop [--dry-run] [--kill] --match comm=<regex> | args=<regex> ...   (patterns are ORed)

`stop` sends SIGTERM to each matching PID, waits up to 20 s, and only with --kill sends SIGKILL to survivors.
It never matches by name through pkill/killall; every PID is read from /proc, its uid must be ours and it
must not be this process or one of its parents. Output: one JSON document.
"""
import json
import os
import re
import signal
import sys
import time

UID = os.getuid()


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


def procs():
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        st = read(f"/proc/{pid}/status").decode(errors="replace")
        m = re.search(r"^Uid:\s+(\d+)", st, re.M)
        if not m or int(m.group(1)) != UID:
            continue
        rss = re.search(r"^VmRSS:\s+(\d+) kB", st, re.M)
        out.append({
            "pid": int(pid),
            "ppid": int((re.search(r"^PPid:\s+(\d+)", st, re.M) or [0, 0])[1]),
            "comm": read(f"/proc/{pid}/comm").decode(errors="replace").strip(),
            "args": read(f"/proc/{pid}/cmdline").replace(b"\0", b" ").decode(errors="replace").strip()[:300],
            "rss_kib": int(rss.group(1)) if rss else 0,
        })
    return sorted(out, key=lambda p: -p["rss_kib"])


def ancestors():
    seen, pid = set(), os.getpid()
    while pid > 1 and pid not in seen:
        seen.add(pid)
        m = re.search(r"^PPid:\s+(\d+)", read(f"/proc/{pid}/status").decode(errors="replace"), re.M)
        pid = int(m.group(1)) if m else 0
    return seen


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    if cmd == "list":
        ps = procs()
        print(json.dumps({"uid": UID, "rss_kib_sum": sum(p["rss_kib"] for p in ps), "procs": ps}))
        return
    if cmd != "stop":
        sys.exit("usage: list | stop")
    dry, kill = "--dry-run" in sys.argv, "--kill" in sys.argv
    pats = []
    argv = sys.argv[2:]
    i = 0
    while i < len(argv):
        if argv[i] == "--match":
            k, _, rx = argv[i + 1].partition("=")
            if k not in ("comm", "args"):
                sys.exit("bad --match")
            pats.append((k, re.compile(rx)))
            i += 2
        else:
            i += 1
    skip = ancestors()
    hit = [p for p in procs() if p["pid"] not in skip and any(rx.search(p[k]) for k, rx in pats)]
    res = {"matched": hit, "terminated": [], "killed": [], "survivors": [], "dry_run": dry}
    if not dry and hit:
        for p in hit:
            try:
                os.kill(p["pid"], signal.SIGTERM)
                res["terminated"].append(p["pid"])
            except ProcessLookupError:
                pass
        end = time.time() + 20
        while time.time() < end and any(os.path.exists(f"/proc/{p['pid']}") and not zombie(p["pid"]) for p in hit):
            time.sleep(0.5)
        left = [p for p in hit if os.path.exists(f"/proc/{p['pid']}") and not zombie(p["pid"])]
        if kill:
            for p in left:
                try:
                    os.kill(p["pid"], signal.SIGKILL)
                    res["killed"].append(p["pid"])
                except ProcessLookupError:
                    pass
            time.sleep(1)
            left = [p for p in left if os.path.exists(f"/proc/{p['pid']}") and not zombie(p["pid"])]
        res["survivors"] = [{"pid": p["pid"], "comm": p["comm"]} for p in left]
    print(json.dumps(res))


def zombie(pid):
    st = read(f"/proc/{pid}/stat").decode(errors="replace")
    return st.rsplit(") ", 1)[-1][:1] == "Z"


if __name__ == "__main__":
    main()

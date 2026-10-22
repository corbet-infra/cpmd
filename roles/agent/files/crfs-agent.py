#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# crfs-agent: the one helper the crfs collection puts on a rented seedbox account (Debian 12, no root, cgroup v1,
# python3 stdlib only). It never reads a password from an argument.
#
#   crfs-agent facts <name>             print the fact sheet of this account as JSON
#   crfs-agent quota [--push]           write ~/cold/status/quota.json (used/limit of disk, files, RAM);
#                                       --push also PUTs it into the account's own S3 endpoint as ops/<name>/quota.json
#   crfs-agent s3 <endpoint> <ca> <env-file> mb|put|get|head|rm|ls <bucket> [key] [file]
#                                       minimal SigV4 client (path style, us-east-1) for smoke tests
#
# Environment: CRFS_PORTS (comma list, ports probed by `facts`, default 9000), CRFS_UNITS (comma list of user
# units reported by `quota`, default rustfs.service).
# Credentials for `s3` and `--push` come from an env file (KEY=VALUE lines, 0600) named by the
# S3_ENV_FILE variable or the argument; they never appear in argv or in output.
import datetime
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

HOME = os.path.expanduser("~")
COLD = os.path.join(HOME, "cold")


# ---------------------------------------------------------------------------------------- helpers
def sh(*argv, timeout=20):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def read(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return default


def to_int(s):
    try:
        return int(s)
    except Exception:
        return None


def parse_size(tok):
    """'308M' -> bytes, '910G' -> bytes, '455k' -> 455*1024 (files use k as 1000 in quota(1); see parse_files)."""
    m = re.fullmatch(r"([0-9.]+)([KMGTP]?)", tok.strip(), re.I)
    if not m:
        return None
    mult = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4, "P": 1024**5}[m.group(2).upper()]
    return int(float(m.group(1)) * mult)


def parse_files(tok):
    m = re.fullmatch(r"([0-9.]+)([kKmM]?)", tok.strip())
    if not m:
        return None
    mult = {"": 1, "k": 1000, "K": 1000, "m": 10**6, "M": 10**6}[m.group(2)]
    return int(float(m.group(1)) * mult)


def parse_quota_text(text):
    """The text of ~/.quota (or `quota -u`): the last line with seven fields after the header.
    Returns bytes for space and counts for files. A grace period column may be empty."""
    for line in reversed(text.splitlines()):
        t = line.split()
        if len(t) >= 7 and t[0].startswith("/"):
            # Filesystem space quota limit [grace] files quota limit [grace]
            rest = t[1:]
            if len(rest) >= 6:
                return {
                    "filesystem": t[0],
                    "used_bytes": parse_size(rest[0]),
                    "quota_bytes": parse_size(rest[1]),
                    "limit_bytes": parse_size(rest[2]),
                    "files_used": parse_files(rest[3]),
                    "files_quota": parse_files(rest[4]),
                    "files_limit": parse_files(rest[5]),
                }
    return None


def cgroup_paths():
    """Paths of the memory, cpu and pids cgroups of this session (v1: one per controller; v2: unified)."""
    out = {}
    for line in read("/proc/self/cgroup").splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        for ctl in parts[1].split(","):
            out[ctl or "unified"] = parts[2]
    return out


def memory_cgroup():
    """Memory limit of the account. The account's slice (user-<uid>.slice) holds the limit, not the session scope."""
    cg = cgroup_paths()
    uid = os.getuid()
    res = {"version": None}
    if "memory" in cg:  # cgroup v1
        res["version"] = 1
        base = "/sys/fs/cgroup/memory"
        cand = [f"{base}/user.slice/user-{uid}.slice", base + cg["memory"]]
        for c in cand:
            lim = to_int(read(c + "/memory.limit_in_bytes"))
            if lim is not None and lim < 1 << 60:
                res.update(
                    path=c.replace(base, ""),
                    limit_bytes=lim,
                    usage_bytes=to_int(read(c + "/memory.usage_in_bytes")),
                    max_usage_bytes=to_int(read(c + "/memory.max_usage_in_bytes")),
                    failcnt=to_int(read(c + "/memory.failcnt")),
                    oom_kill=to_int((re.search(r"oom_kill (\d+)", read(c + "/memory.oom_control")) or [0, None])[1]),
                )
                stat = read(c + "/memory.stat")
                for key in ("total_cache", "total_rss", "total_mapped_file"):
                    m = re.search(rf"^{key} (\d+)$", stat, re.M)
                    if m:
                        res["stat_" + key] = int(m.group(1))
                return res
    elif "unified" in cg:  # cgroup v2
        res["version"] = 2
        base = "/sys/fs/cgroup"
        for c in (f"{base}/user.slice/user-{uid}.slice", base + cg["unified"]):
            mx = read(c + "/memory.max")
            if mx:
                res.update(
                    path=c.replace(base, ""),
                    limit_bytes=None if mx == "max" else to_int(mx),
                    usage_bytes=to_int(read(c + "/memory.current")),
                    oom_kill=to_int((re.search(r"oom_kill (\d+)", read(c + "/memory.events")) or [0, None])[1]),
                )
                return res
    return res


def cpu_cgroup():
    cg = cgroup_paths()
    uid = os.getuid()
    res = {}
    if "cpu" in cg or "cpu,cpuacct" in cg:
        base = "/sys/fs/cgroup/cpu"
        c = f"{base}/user.slice/user-{uid}.slice"
        q, p = to_int(read(c + "/cpu.cfs_quota_us")), to_int(read(c + "/cpu.cfs_period_us"))
        res = {"version": 1, "cfs_quota_us": q, "cfs_period_us": p, "shares": to_int(read(c + "/cpu.shares"))}
        if q and q > 0 and p:
            res["cores"] = q / p
    elif "unified" in cg:
        mx = read(f"/sys/fs/cgroup/user.slice/user-{uid}.slice/cpu.max").split()
        res = {"version": 2, "max": mx}
        if len(mx) == 2 and mx[0] != "max":
            res["cores"] = int(mx[0]) / int(mx[1])
    pids = read(f"/sys/fs/cgroup/pids/user.slice/user-{uid}.slice/pids.max")
    if pids:
        res["pids_max"] = to_int(pids) if pids != "max" else None
    return res


def disk():
    q = None
    txt = read(os.path.join(HOME, ".quota"))
    src = "~/.quota"
    if txt:
        q = parse_quota_text(txt)
    if q is None:
        q = parse_quota_text(sh("quota", "-u", "-w", "-p"))
        src = "quota -u"
    res = {"source": src if q else None}
    if q:
        res.update(q)
    st = os.statvfs(HOME)
    res["fs_total_bytes"] = st.f_blocks * st.f_frsize
    res["fs_free_bytes"] = st.f_bavail * st.f_frsize
    res["fs_inodes_free"] = st.f_favail
    mounts = [l.split() for l in read("/proc/mounts").splitlines()]
    best = ""
    for m in mounts:
        if len(m) > 2 and (HOME == m[1] or HOME.startswith(m[1].rstrip("/") + "/")) and len(m[1]) > len(best):
            best, res["mount"] = m[1], {"device": m[0], "target": m[1], "fstype": m[2]}
    return res


def own_processes():
    uid = os.getuid()
    procs, total = [], 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            if os.stat(f"/proc/{pid}").st_uid != uid:
                continue
            status = read(f"/proc/{pid}/status")
            rss = int((re.search(r"VmRSS:\s+(\d+) kB", status) or [0, 0])[1]) * 1024
            comm = read(f"/proc/{pid}/comm")
        except Exception:
            continue
        total += rss
        procs.append((rss, int(pid), comm))
    procs.sort(reverse=True)
    return total, procs


def unit_state(name):
    return {
        "active": sh("systemctl", "--user", "is-active", name) or "unknown",
        "enabled": sh("systemctl", "--user", "is-enabled", name) or "unknown",
    }


def main_pid_rss(unit):
    pid = to_int(sh("systemctl", "--user", "show", "-p", "MainPID", "--value", unit))
    if not pid:
        return None
    m = re.search(r"VmRSS:\s+(\d+) kB", read(f"/proc/{pid}/status"))
    return {"pid": pid, "rss_bytes": int(m.group(1)) * 1024} if m else None


# ---------------------------------------------------------------------------------------- facts
def assigned_ports():
    out = {}
    for fn in sorted(os.listdir(HOME)):
        if re.fullmatch(r"\.(.*[pP]ort.*|media-stack-port-.*)", fn):
            v = read(os.path.join(HOME, fn)).strip()
            if re.fullmatch(r"\d{2,5}", v):
                out[fn.lstrip(".")] = int(v)
    return out


def listening_own():
    res = []
    for line in sh("ss", "-tlnpH").splitlines():
        t = line.split()
        if len(t) >= 6 and "users:" in line:
            res.append(t[3])
    return sorted(res)


def can_bind(port):
    s = socket.socket()
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        return True
    except OSError as e:
        return f"no: {e.strerror}"
    finally:
        s.close()


def traffic():
    res = {"limit_raw": read(os.path.join(HOME, ".trafficLimit"))}
    txt = read(os.path.join(HOME, ".trafficData"))
    for key in ("month", "week", "day"):
        m = re.search(rf'"{key}";d:([0-9.eE+-]+)', txt)
        if m:
            res[key] = float(m.group(1))
    return res


def facts(name):
    uid = os.getuid()
    now = datetime.datetime.now(datetime.timezone.utc)
    boot_id = read("/proc/sys/kernel/random/boot_id")
    meminfo = read("/proc/meminfo")
    mem_total = int(re.search(r"MemTotal:\s+(\d+)", meminfo).group(1)) * 1024
    cpu_model = (re.search(r"model name\s*:\s*(.+)", read("/proc/cpuinfo")) or [0, ""])[1]
    osrel = dict(l.split("=", 1) for l in read("/etc/os-release").splitlines() if "=" in l)
    addrs = []
    for line in sh("ip", "-4", "-o", "addr").splitlines():
        t = line.split()
        if len(t) >= 4:
            addrs.append({"dev": t[1], "cidr": t[3]})
    route = sh("ip", "-4", "route", "show", "default")
    mac = read("/sys/class/net/eth0/address")
    own_total, own_top = own_processes()
    dmi = {k: read(f"/sys/class/dmi/id/{k}") for k in ("sys_vendor", "product_name", "bios_vendor", "bios_version")}
    hostname = socket.gethostname()
    fq = socket.getfqdn()
    host_ports = assigned_ports()
    wanted = [int(x) for x in os.environ.get("CRFS_PORTS", "9000").split(",") if x.strip()]
    cold = {}
    for sub in ("bin", "etc", "tls", "data", "status"):
        p = os.path.join(COLD, sub)
        cold[sub] = sorted(os.listdir(p)) if os.path.isdir(p) else None
    rustfs_bin = os.path.join(COLD, "bin", "rustfs", "rustfs")
    versions = {}
    if os.access(rustfs_bin, os.X_OK):
        versions["rustfs"] = sh(rustfs_bin, "--version")[:120]
    return {
        "box": name,
        "collected_at": now.isoformat(timespec="seconds"),
        "identity": {
            "user": os.environ.get("USER") or sh("id", "-un"),
            "uid": uid,
            "hostname": hostname,
            "etc_hostname": read("/etc/hostname"),
            "fqdn": fq,
            "public_ipv4": [a["cidr"].split("/")[0] for a in addrs if a["dev"] == "eth0"],
        },
        "os": {
            "pretty": osrel.get("PRETTY_NAME", "").strip('"'),
            "kernel": os.uname().release,
            "virt": sh("systemd-detect-virt") or None,
            "python": sys.version.split()[0],
            "curl": (sh("curl", "--version").split() + ["", ""])[1],
            "openssl": (sh("openssl", "version").split() + ["", ""])[1],
            "systemd": (sh("systemctl", "--version").split() + ["", ""])[1],
            "tools": {t: bool(sh("which", t)) for t in ("unzip", "tar", "xz", "sha256sum", "screen", "tmux", "jq", "docker")},
        },
        "limits": {
            "memory": memory_cgroup(),
            "cpu": cpu_cgroup(),
            "disk": disk(),
            "traffic": traffic(),
            "nofile": read("/proc/self/limits").split("Max open files")[1].split()[0:2] if "Max open files" in read("/proc/self/limits") else None,
            "oom_kill_status_file": read(os.path.join(HOME, ".oomKillStatus")) or None,
        },
        "ports": {
            "assigned_files": host_ports,
            "ours": {str(p): can_bind(p) for p in wanted},
            "own_listening": listening_own(),
        },
        "network": {"addresses": addrs, "default_route": route, "eth0_mac": mac},
        "physical_hint": {
            # A seedbox is a VM on a shared Debian host; nothing inside it names the hypervisor. These facts
            # are the best grouping hints: the same boot_id and MemTotal mean the same VM (two accounts on one
            # VM); the /25 and the gateway mean the same rack segment; the virtio MAC prefix says nothing.
            "boot_id_sha256_12": hashlib.sha256(boot_id.encode()).hexdigest()[:12],
            "booted_at": datetime.datetime.fromtimestamp(
                int(re.search(r"btime (\d+)", read("/proc/stat")).group(1)), datetime.timezone.utc
            ).isoformat(timespec="seconds"),
            "mem_total_bytes": mem_total,
            "cpu_model": cpu_model,
            "cpus_visible": len(os.sched_getaffinity(0)),
            "dmi": dmi,
            "subnet": next((a["cidr"] for a in addrs if a["dev"] == "eth0"), None),
            "gateway": (re.search(r"via (\S+)", route) or [0, None])[1],
            "home_filesystem": disk().get("mount"),
            "home_fs_total_bytes": disk().get("fs_total_bytes"),
            "accounts_on_host": len(os.listdir("/home")) if os.access("/home", os.R_OK | os.X_OK) else None,
        },
        "systemd_user": {
            "state": sh("systemctl", "--user", "is-system-running"),
            "linger_file": os.path.exists(f"/var/lib/systemd/linger/{os.environ.get('USER', '')}"),
            "pulsed_manager_status": read(os.path.join(HOME, ".systemd-user-status.json")) or None,
        },
        "own_memory": {
            "rss_sum_bytes": own_total,
            "top": [{"pid": p, "comm": c, "rss_bytes": r} for r, p, c in own_top[:8]],
        },
        "installed": {"versions": versions, "cold_dirs": cold,
                      "units": {u: unit_state(u) for u in ("rustfs.service", "crfs-quota.timer", "docker.service")}},
        "clock": {"timezone": sh("date", "+%Z %z"), "ntp_synchronized": sh("timedatectl", "show", "-p", "NTPSynchronized", "--value") or None},
    }


# ---------------------------------------------------------------------------------------- quota
def quota_doc(name):
    mem = memory_cgroup()
    d = disk()
    total, top = own_processes()
    doc = {
        "box": name,
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "disk": {k: d.get(k) for k in ("used_bytes", "quota_bytes", "limit_bytes", "files_used", "files_quota", "files_limit")},
        "memory": {k: mem.get(k) for k in ("limit_bytes", "usage_bytes", "max_usage_bytes", "failcnt", "oom_kill", "stat_total_cache", "stat_total_rss")},
        "own_rss_bytes": total,
        "traffic": traffic(),
        "services": {},
    }
    for u in [x for x in os.environ.get("CRFS_UNITS", "rustfs.service").split(",") if x.strip()]:
        st = unit_state(u)
        if st["active"] == "active":
            st["main"] = main_pid_rss(u)
        doc["services"][u] = st
    q = doc["disk"]
    if q["used_bytes"] and q["quota_bytes"]:
        doc["disk"]["used_fraction"] = round(q["used_bytes"] / q["quota_bytes"], 4)
    if q["files_used"] and q["files_quota"]:
        doc["disk"]["files_fraction"] = round(q["files_used"] / q["files_quota"], 4)
    return doc


# ---------------------------------------------------------------------------------------- S3 (SigV4)
def load_env(path):
    env = {}
    for line in read(path).splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"')
    return env


def _hm(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4_headers(method, host, canon_path, query, headers, payload, access, secret, region, amz):
    """AWS Signature V4 for S3. `headers` are lower-case extras (host and the x-amz-* ones are added here).
    Returns the full header dict including `authorization`."""
    day = amz[:8]
    headers = dict(headers)
    headers.update({"host": host, "x-amz-date": amz, "x-amz-content-sha256": payload})
    signed = ";".join(sorted(headers))
    canon_h = "".join(f"{k}:{headers[k].strip()}\n" for k in sorted(headers))
    canon = "\n".join([method, canon_path, query, canon_h, signed, payload])
    scope = f"{day}/{region}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canon.encode()).hexdigest()])
    k = _hm(_hm(_hm(_hm(("AWS4" + secret).encode(), day), region), "s3"), "aws4_request")
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return headers


def s3_request(endpoint, ca, access, secret, method, path, body=b"", query="", extra=None, region="us-east-1"):
    u = urllib.parse.urlparse(endpoint)
    amz = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    canon_path = urllib.parse.quote(path, safe="/-_.~")
    headers = sigv4_headers(method, u.netloc, canon_path, query, {k.lower(): v for k, v in (extra or {}).items()},
                            hashlib.sha256(body).hexdigest(), access, secret, region, amz)
    if u.scheme == "https":
        ctx = ssl.create_default_context(cafile=ca) if ca and ca != "-" else ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=60)
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=60)
    try:
        conn.request(method, canon_path + (("?" + query) if query else ""), body=body if body else None, headers=headers)
        r = conn.getresponse()
        data = r.read()
        return r.status, dict(r.getheaders()), data
    finally:
        conn.close()


def cmd_s3(argv):
    endpoint, ca, envfile, op = argv[:4]
    env = load_env(envfile)
    access, secret = env["S3_ACCESS_KEY"], env["S3_SECRET_KEY"]
    bucket = argv[4]
    key = argv[5] if len(argv) > 5 else ""
    path = "/" + bucket + (("/" + key) if key else "")
    if op == "mb":
        st, _, data = s3_request(endpoint, ca, access, secret, "PUT", path)
    elif op == "put":
        with open(argv[6], "rb") as f:
            body = f.read()
        st, _, data = s3_request(endpoint, ca, access, secret, "PUT", path, body=body)
    elif op == "get":
        st, _, data = s3_request(endpoint, ca, access, secret, "GET", path)
        if st == 200 and len(argv) > 6:
            with open(argv[6], "wb") as f:
                f.write(data)
            data = b""
    elif op == "head":
        st, h, data = s3_request(endpoint, ca, access, secret, "HEAD", path)
        data = json.dumps({"content-length": h.get("Content-Length")}).encode()
    elif op == "rm":
        st, _, data = s3_request(endpoint, ca, access, secret, "DELETE", path)
    elif op == "ls":
        st, _, data = s3_request(endpoint, ca, access, secret, "GET", "/" + bucket, query="list-type=2")
        if st == 200:
            data = b"\n".join(re.findall(rb"<Key>([^<]+)</Key>", data))
    else:
        print("unknown op", op, file=sys.stderr)
        return 2
    print(st)
    if data:
        sys.stdout.flush()
        sys.stdout.buffer.write(data[:2000] + b"\n")
    return 0 if st in (200, 204) else 1


def trim_log(path, keep=32 * 1024 * 1024, limit=64 * 1024 * 1024):
    """Keep the unit log from growing without bound: above `limit` bytes keep the last `keep` bytes (in place, the
    writer has the file open in append mode)."""
    try:
        size = os.path.getsize(path)
        if size <= limit:
            return
        with open(path, "rb") as f:
            f.seek(size - keep)
            tail = f.read()
        with open(path, "r+b") as f:
            f.write(tail)
            f.truncate(len(tail))
    except OSError:
        pass


def cmd_quota(argv):
    trim_log(os.path.join(COLD, "log", "rustfs.log"))
    name = os.environ.get("BOX_NAME") or read(os.path.join(COLD, "etc", "box-name")) or socket.gethostname().split(".")[0]
    doc = quota_doc(name)
    out = os.environ.get("QUOTA_OUT") or os.path.join(COLD, "status", "quota.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
    os.replace(tmp, out)
    if "--push" in argv:
        envfile = os.environ.get("S3_ENV_FILE") or os.path.join(COLD, "etc", "s3-ops.env")
        env = load_env(envfile)
        if env:
            ca = os.path.join(COLD, "tls", "ca.pem")
            bucket = env.get("S3_OPS_BUCKET", "crfs-ops")
            st = None
            try:
                args = (env["S3_ENDPOINT"], ca, env["S3_ACCESS_KEY"], env["S3_SECRET_KEY"])
                st, _, _ = s3_request(*args, "PUT", f"/{bucket}/ops/{name}/quota.json", body=json.dumps(doc).encode())
                if st == 404:  # no bucket yet
                    s3_request(*args, "PUT", f"/{bucket}")
                    st, _, _ = s3_request(*args, "PUT", f"/{bucket}/ops/{name}/quota.json", body=json.dumps(doc).encode())
            except Exception as e:
                print("push failed:", type(e).__name__, file=sys.stderr)
            print("push", st)
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == "facts":
        print(json.dumps(facts(sys.argv[2] if len(sys.argv) > 2 else ""), indent=1, sort_keys=True))
        return 0
    if cmd == "quota":
        return cmd_quota(sys.argv[2:])
    if cmd == "s3":
        return cmd_s3(sys.argv[2:])
    print("unknown command", cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

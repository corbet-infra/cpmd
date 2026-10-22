# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-3.0-or-later
from __future__ import annotations

DOCUMENTATION = r"""
name: sops_accounts
author: Julian Y. Richard Corbet
short_description: inventory of rented seedbox accounts from sops files
description:
  - Builds hosts from one or more sops-encrypted files. A source is either a file holding a LIST of accounts
    (O(sources[].list_key)) or a file that is a single account. Every account needs a host name (DNS name or
    address), an SSH user and an SSH password; other plain fields are kept in the host variable C(crfs_attrs).
  - The SSH password is NEVER put into the inventory as text. With O(auth=password) the host variable
    C(ansible_password) is a lookup template that reads that one value through the C(corbet.crfs.sops)
    lookup when a task needs it, so C(ansible-inventory --list) shows the template only. With O(auth=key) the
    admin private key (a sops value) is written to a 0600 file under /dev/shm for the life of the process and
    shredded at exit; the host variable C(crfs_admin_key_file) names it.
  - Host keys are never trusted on first use by the connection, so O(known_hosts) must hold the pinned keys
    (the C(tools/scan-hostkeys) script of the collection fills it).
options:
  plugin:
    description: Must be C(corbet.crfs.sops_accounts).
    required: true
    choices: ['corbet.crfs.sops_accounts']
  sources:
    description:
      - List of sources. Each is a dict with C(file) (absolute, or relative to the inventory file), C(group)
        (inventory group), and for a list file C(list_key) and either C(prefix) (hosts are named C(<prefix>01), ...)
        or C(name_format) (for example C(node-{i}), with C(index_start), default 0). Optional C(sort_by) names a field
        of the entries and C(sort_regex) a regex whose first group is extracted from it; entries are numbered in
        ascending order of that key (numeric when it is all digits), otherwise in file order. For a single-account
        file give C(name). Optional C(host_key), C(user_key), C(password_key) rename the keys (defaults C(host),
        C(ssh_user), C(ssh_password)).
    type: list
    elements: dict
    required: true
  known_hosts:
    description: Pinned host keys file used for every connection (StrictHostKeyChecking=yes). Relative to the inventory file.
    required: true
  auth:
    description: C(password) for the bootstrap, C(key) once the admin key is installed.
    default: password
    choices: [password, key]
    env:
      - name: CRFS_AUTH
  admin_key:
    description: Dict with C(file) and C(key) of the sops value that holds the admin private key. Needed for O(auth=key).
    type: dict
    default: {}
"""

EXAMPLES = r"""
# inventory/accounts.sops_accounts.yml
plugin: corbet.crfs.sops_accounts
known_hosts: ../known_hosts
sources:
  - file: /path/to/accounts.sops.yml     # contains: accounts: [{host: ..., ssh_user: ..., ssh_password: ...}, ...]
    list_key: accounts
    prefix: node
    group: cluster
  - file: /path/to/playground.sops.yml   # contains: host, ssh_user, ssh_password
    name: playground
    group: testbox
admin_key:
  file: /path/to/admin-key.sops.yml
  key: admin_ssh_key
"""

import atexit
import json
import os
import re
import socket
import subprocess
import tempfile

from ansible.errors import AnsibleParserError
from ansible.plugins.inventory import BaseInventoryPlugin

try:  # ansible-core >= 2.19 does not template inventory strings unless they are marked as trusted templates
    from ansible.template import trust_as_template
except ImportError:  # pragma: no cover
    def trust_as_template(value):
        return value

_SHRED = []
_SECRETISH = re.compile(r"pass|secret|key|token|cred", re.I)


def _cleanup():
    for p in _SHRED:
        if os.path.exists(p):
            subprocess.run(["shred", "-u", p], check=False)


atexit.register(_cleanup)


def sops_json(path):
    r = subprocess.run(["sops", "--decrypt", "--output-type", "json", path], capture_output=True, text=True)
    if r.returncode != 0:
        raise AnsibleParserError("sops could not decrypt %s" % os.path.basename(path))
    return json.loads(r.stdout)


def sops_value(path, key):
    r = subprocess.run(["sops", "--decrypt", "--extract", '["%s"]' % key, path], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        raise AnsibleParserError("sops could not extract %s from %s" % (key, os.path.basename(path)))
    return r.stdout


class InventoryModule(BaseInventoryPlugin):
    NAME = "corbet.crfs.sops_accounts"

    def verify_file(self, path):
        return super().verify_file(path) and path.endswith(("sops_accounts.yml", "sops_accounts.yaml"))

    @staticmethod
    def _common_args(known_hosts, auth):
        a = ["-o", "UserKnownHostsFile=%s" % known_hosts, "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
             "-o", "ServerAliveInterval=15", "-o", "ConnectTimeout=20"]
        if auth == "key":
            a += ["-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no", "-o", "PreferredAuthentications=publickey"]
        else:
            a += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1"]
        return " ".join(a)

    @staticmethod
    def _resolve(name):
        try:
            return socket.gethostbyname(name)
        except OSError as e:
            raise AnsibleParserError("cannot resolve %s: %s" % (name, e))

    def parse(self, inventory, loader, path, cache=True):
        super().parse(inventory, loader, path, cache)
        self._read_config_data(path)
        base = os.path.dirname(os.path.abspath(path))

        def rel(p):
            p = os.path.expanduser(p)
            return p if os.path.isabs(p) else os.path.normpath(os.path.join(base, p))

        auth = self.get_option("auth")
        known_hosts = rel(self.get_option("known_hosts"))
        common = self._common_args(known_hosts, auth)

        keyfile = None
        if auth == "key":
            ak = self.get_option("admin_key") or {}
            if not ak.get("file") or not ak.get("key") or not os.path.exists(rel(ak["file"])):
                raise AnsibleParserError("auth=key needs admin_key.file (existing) and admin_key.key")
            fd, keyfile = tempfile.mkstemp(prefix="crfs-admin-key.", dir="/dev/shm")
            _SHRED.append(keyfile)
            os.write(fd, sops_value(rel(ak["file"]), ak["key"]).rstrip("\n").encode() + b"\n")
            os.close(fd)
            os.chmod(keyfile, 0o600)

        def add(alias, entry, src, pw_ref, index):
            group = src["group"]
            self.inventory.add_group(group)
            self.inventory.add_host(alias, group=group)
            v = self.inventory.set_variable
            host, user = entry[src.get("host_key", "host")], entry[src.get("user_key", "ssh_user")]
            skip = {src.get("host_key", "host"), src.get("user_key", "ssh_user"), src.get("password_key", "ssh_password")}
            attrs = {k: val for k, val in entry.items() if k not in skip and not _SECRETISH.search(k) and isinstance(val, (str, int, float, bool))}
            v(alias, "ansible_host", self._resolve(host))
            v(alias, "ansible_user", user)
            v(alias, "ansible_port", 22)
            v(alias, "ansible_python_interpreter", "/usr/bin/python3")
            v(alias, "ansible_ssh_common_args", common)
            v(alias, "crfs_label", host)
            v(alias, "crfs_index", index)
            v(alias, "crfs_attrs", attrs)
            if auth == "key":
                v(alias, "ansible_ssh_private_key_file", keyfile)
                v(alias, "crfs_admin_key_file", keyfile)
            else:
                v(alias, "ansible_password", trust_as_template(pw_ref))

        for src in self.get_option("sources"):
            for need in ("file", "group"):
                if need not in src:
                    raise AnsibleParserError("each source needs '%s'" % need)
            fn = rel(src["file"])
            pwk = src.get("password_key", "ssh_password")
            doc = sops_json(fn)
            if "list_key" in src:
                if "prefix" not in src and "name_format" not in src:
                    raise AnsibleParserError("a list source needs 'prefix' or 'name_format'")
                entries = list(enumerate(doc.get(src["list_key"], [])))
                if src.get("sort_by"):
                    rx = re.compile(src.get("sort_regex", r"(.*)"))

                    def key(item):
                        m = rx.search(str(item[1].get(src["sort_by"], "")))
                        k = m.group(1) if m else ""
                        return (0, int(k), "") if k.isdigit() else (1, 0, k)

                    entries.sort(key=key)
                start = int(src.get("index_start", 0 if "name_format" in src else 1))
                for pos, (orig, entry) in enumerate(entries):
                    n = pos + start
                    alias = src["name_format"].format(i=n) if "name_format" in src else "%s%02d" % (src["prefix"], n)
                    ref = "{{ lookup('corbet.crfs.sops', '%s', '%s.%d.%s') }}" % (fn, src["list_key"], orig, pwk)
                    add(alias, entry, src, ref, n)
            else:
                if "name" not in src:
                    raise AnsibleParserError("a single-account source needs 'name'")
                ref = "{{ lookup('corbet.crfs.sops', '%s', '%s') }}" % (fn, pwk)
                add(src["name"], doc, src, ref, 0)
